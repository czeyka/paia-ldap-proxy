package main

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "strconv"
    "strings"
    "time"
)

const (
    ldapSequence = 0x30
    ldapInteger  = 0x02
    ldapString   = 0x04
    ldapEnum     = 0x0A
    ldapBindReq  = 0x60
    ldapBindRes  = 0x61
    ldapSearchReq = 0x63
    ldapSearchResEntry = 0x64
    ldapSearchResDone  = 0x65

    ldapResultSuccess = 0
    ldapResultInvalidCreds = 49
    ldapResultNoSuchObject = 32
    ldapResultUnwilling = 53
)

type config struct {
    BaseURL string
    Isil string
    AuthURL string
    CoreURL string
    Listen string
    BaseDN string
}

type patron struct {
    Name string `json:"name"`
    Email string `json:"email"`
    Status int `json:"status"`
    Node string `json:"node"`
}

func main() {
    cfg := loadConfig()
    ln, err := net.Listen("tcp", cfg.Listen)
    if err != nil { log.Fatal(err) }
    defer ln.Close()
    log.Printf("PAIA LDAP proxy listening on %s", cfg.Listen)
    for {
        conn, err := ln.Accept()
        if err != nil { log.Printf("accept: %v", err); continue }
        go handleConn(conn, cfg)
    }
}

func loadConfig() config {
    base := strings.TrimRight(os.Getenv("PAIA_BASE_URL"), "/")
    if base == "" { base = "https://paia.gbv.de" }
    isil := strings.TrimSpace(os.Getenv("PAIA_ISIL"))
    if isil == "" { isil = "DE-841" }
    authPath := strings.Trim(os.Getenv("PAIA_AUTH_PATH"), "/")
    if authPath == "" { authPath = "auth" }
    corePath := strings.Trim(os.Getenv("PAIA_CORE_PATH"), "/")
    if corePath == "" { corePath = "core" }
    listen := os.Getenv("LDAP_LISTEN")
    if listen == "" { listen = ":389" }
    baseDN := os.Getenv("LDAP_BASE_DN")
    if baseDN == "" { baseDN = "dc=library,dc=local" }
    return config{
        BaseURL: base,
        Isil: isil,
        AuthURL: strings.TrimRight(base, "/") + "/" + strings.Trim(isil, "/") + "/" + authPath,
        CoreURL: strings.TrimRight(base, "/") + "/" + strings.Trim(isil, "/") + "/" + corePath,
        Listen: listen,
        BaseDN: baseDN,
    }
}

func handleConn(conn net.Conn, cfg config) {
    defer conn.Close()
    if err := conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil { log.Printf("deadline: %v", err) }
    buf := make([]byte, 65535)
    n, err := conn.Read(buf)
    if err != nil {
        if err != io.EOF { log.Printf("read: %v", err) }
        return
    }
    msg, err := decodeLDAPMessage(buf[:n])
    if err != nil {
        _ = sendLDAPResult(conn, 1, ldapBindRes, ldapResultInvalidCreds, "", "bad LDAP packet")
        return
    }

    switch msg.op {
    case ldapBindReq:
        username, password, ok := parseSimpleBind(msg.payload)
        if !ok {
            _ = sendLDAPResult(conn, msg.id, ldapBindRes, ldapResultInvalidCreds, "", "missing bind creds")
            return
        }
        pat, err := paiaLoginAndPatron(cfg, username, password)
        if err != nil {
            _ = sendLDAPResult(conn, msg.id, ldapBindRes, ldapResultInvalidCreds, "", err.Error())
            return
        }
        // success
        _ = sendLDAPResult(conn, msg.id, ldapBindRes, ldapResultSuccess, "", "OK")
        _ = sendLDAPSearchEntry(conn, msg.id, pat, cfg)
        _ = sendLDAPDone(conn, msg.id)

    case ldapSearchReq:
        username := extractSearchUsername(msg.payload)
        if username == "" {
            _ = sendLDAPDone(conn, msg.id)
            return
        }
        pat, err := paiaLoginAndPatron(cfg, username, "")
        if err != nil {
            _ = sendLDAPResult(conn, msg.id, ldapSearchResDone, ldapResultNoSuchObject, "", err.Error())
            return
        }
        _ = sendLDAPSearchEntry(conn, msg.id, pat, cfg)
        _ = sendLDAPDone(conn, msg.id)

    default:
        _ = sendLDAPResult(conn, msg.id, ldapBindRes, ldapResultUnwilling, "", "unsupported")
    }
}

func decodeLDAPMessage(data []byte) (struct { id int; op byte; payload []byte }, error) {
    var out struct { id int; op byte; payload []byte }
    if len(data) < 2 || data[0] != ldapSequence { return out, fmt.Errorf("not ldap sequence") }
    _, _, next, err := readElement(data, 0)
    if err != nil { return out, err }
    if next > len(data) { return out, fmt.Errorf("truncated") }

    inner := data[2:next]
    if len(inner) < 2 { return out, fmt.Errorf("too short") }
    tag, val, pos, err := readElement(inner, 0)
    if err != nil || tag != ldapInteger { return out, fmt.Errorf("missing msg id") }
    out.id = int(val[0])
    if len(val) > 1 { out.id = int(binaryFromBytes(val)) }

    tag, val, _, err = readElement(inner, pos)
    if err != nil { return out, err }
    out.op = tag
    out.payload = val
    return out, nil
}

func parseSimpleBind(data []byte) (string, string, bool) {
    if len(data) == 0 { return "", "", false }
    // payload is a SEQUENCE of version, dn, auth
    tag, seq, _, err := readElement(data, 0)
    if err != nil || tag != ldapSequence { return "", "", false }
    off := 0
    _, _, off, err = readElement(seq, off)
    if err != nil { return "", "", false }
    tag, dn, off, err := readElement(seq, off)
    if err != nil || tag != ldapString { return "", "", false }
    user := string(dn)
    if off >= len(seq) { return user, "", false }
    tag, pass, _, err := readElement(seq, off)
    if err != nil { return user, "", false }
    if tag == 0x80 || tag == ldapString {
        return user, string(pass), true
    }
    return user, "", false
}

func extractSearchUsername(payload []byte) string {
    if len(payload) == 0 { return "" }
    tag, seq, _, err := readElement(payload, 0)
    if err != nil || tag != ldapSequence { return "" }
    // first element is baseObject, then scope, etc.; flatten any string with uid= or sAMAccountName=
    for off := 0; off < len(seq); {
        tag2, val, next, err := readElement(seq, off)
        if err != nil { break }
        if tag2 == ldapString {
            s := string(val)
            if strings.Contains(s, "uid=") || strings.Contains(s, "sAMAccountName=") {
                return strings.TrimPrefix(s, "uid=")
            }
            if strings.Contains(s, "=") && len(s) > 0 {
                if strings.Contains(s, "uid") || strings.Contains(s, "sAMAccountName") {
                    return strings.TrimPrefix(s, "uid=")
                }
            }
        }
        off = next
    }
    return ""
}

func paiaLoginAndPatron(cfg config, username, password string) (patron, error) {
    if strings.TrimSpace(username) == "" { return patron{}, fmt.Errorf("missing username") }
    form := url.Values{}
    form.Set("username", username)
    form.Set("password", password)
    form.Set("grant_type", "password")
    form.Set("scope", "read_patron read_items read_fees read_availability write_items")
    req, err := http.NewRequest(http.MethodPost, cfg.AuthURL+"/login", strings.NewReader(form.Encode()))
    if err != nil { return patron{}, err }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("Accept", "application/json")
    httpClient := &http.Client{Timeout: 12 * time.Second}
    resp, err := httpClient.Do(req)
    if err != nil { return patron{}, err }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        body, _ := io.ReadAll(resp.Body)
        return patron{}, fmt.Errorf("PAIA auth failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
    }
    var tok struct { AccessToken string `json:"access_token"` }
    if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil { return patron{}, err }
    if tok.AccessToken == "" { return patron{}, fmt.Errorf("empty access_token") }

    patronReq, err := http.NewRequest(http.MethodGet, cfg.CoreURL+"/"+url.PathEscape(username), nil)
    if err != nil { return patron{}, err }
    patronReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
    patronReq.Header.Set("Accept", "application/json")
    pres, err := httpClient.Do(patronReq)
    if err != nil { return patron{}, err }
    defer pres.Body.Close()
    if pres.StatusCode < 200 || pres.StatusCode >= 300 {
        body, _ := io.ReadAll(pres.Body)
        return patron{}, fmt.Errorf("PAIA patron lookup failed: %s %s", pres.Status, strings.TrimSpace(string(body)))
    }
    var p patron
    if err := json.NewDecoder(pres.Body).Decode(&p); err != nil { return patron{}, err }
    if p.Name == "" { p.Name = username }
    if p.Email == "" { p.Email = username + "@local" }
    return p, nil
}

func sendLDAPResult(conn net.Conn, msgID int, op byte, code int, matchedDN, diagnostic string) error {
    payload := encodeLDAPResult(code, matchedDN, diagnostic)
    _, err := conn.Write(encodeLDAPMessage(msgID, op, payload))
    return err
}

func sendLDAPDone(conn net.Conn, msgID int) error {
    return sendLDAPResult(conn, msgID, ldapSearchResDone, ldapResultSuccess, "", "")
}

func sendLDAPSearchEntry(conn net.Conn, msgID int, p patron, cfg config) error {
    attrs := []struct{ name string; values []string }{
        {"objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
        {"uid", []string{p.Name}},
        {"cn", []string{p.Name}},
        {"sn", []string{p.Name}},
        {"mail", []string{p.Email}},
        {"displayName", []string{p.Name}},
        {"accountState", []string{strconv.Itoa(p.Status)}},
        {"paiaStatus", []string{strconv.Itoa(p.Status)}},
        {"memberOf", []string{"PAIA"}},
    }
    if p.Node != "" { attrs = append(attrs, struct{ name string; values []string }{"departmentNumber", []string{p.Node}}) }

    entry := encodeSearchEntry("uid="+p.Name+","+cfg.BaseDN, attrs)
    _, err := conn.Write(encodeLDAPMessage(msgID, ldapSearchResEntry, entry))
    return err
}

func encodeLDAPMessage(msgID int, op byte, payload []byte) []byte {
    body := append(encodeInt(msgID), append([]byte{op}, append(encodeLen(len(payload)), payload...)...)...)
    return append([]byte{ldapSequence}, append(encodeLen(len(body)), body...)...)
}

func encodeLDAPResult(code int, matchedDN, diag string) []byte {
    var out []byte
    out = append(out, encodeEnum(code)...)
    out = append(out, encodeString(matchedDN)...)
    out = append(out, encodeString(diag)...)
    return out
}

func encodeSearchEntry(dn string, attrs []struct{ name string; values []string }) []byte {
    var attrSeq []byte
    for _, a := range attrs {
        vals := []byte{}
        for _, v := range a.values {
            vals = append(vals, encodeString(v)...)
        }
        attr := encodeSequence(encodeString(a.name), vals)
        attrSeq = append(attrSeq, attr...)
    }
    return encodeSequence(encodeString(dn), encodeSequence(attrSeq...))
}

func encodeSequence(items ...[]byte) []byte {
    var b []byte
    for _, it := range items { b = append(b, it...) }
    return append([]byte{ldapSequence}, append(encodeLen(len(b)), b...)...)
}

func encodeString(s string) []byte {
    if s == "" { return []byte{ldapString, 0x00} }
    return append([]byte{ldapString}, append(encodeLen(len(s)), []byte(s)...)...)
}

func encodeEnum(v int) []byte {
    return append([]byte{ldapEnum}, append(encodeLen(1), byte(v))...)
}

func encodeInt(v int) []byte {
    if v == 0 { return []byte{ldapInteger, 0x01, 0x00} }
    var b []byte
    for v > 0 {
        b = append([]byte{byte(v & 0xff)}, b...)
        v >>= 8
    }
    return append([]byte{ldapInteger, byte(len(b))}, b...)
}

func encodeLen(n int) []byte {
    if n < 0x80 { return []byte{byte(n)} }
    var b []byte
    for n > 0 {
        b = append([]byte{byte(n & 0xff)}, b...)
        n >>= 8
    }
    return append([]byte{0x80 | byte(len(b))}, b...)
}

func readElement(data []byte, off int) (byte, []byte, int, error) {
    if off >= len(data) { return 0, nil, off, fmt.Errorf("eof") }
    tag := data[off]
    off++
    if off >= len(data) { return 0, nil, off, fmt.Errorf("truncated length") }
    length, consumed, err := readLen(data, off)
    if err != nil { return 0, nil, off, err }
    off += consumed
    if off+length > len(data) { return 0, nil, off, fmt.Errorf("length overflow") }
    val := append([]byte(nil), data[off:off+length]...)
    return tag, val, off + length, nil
}

func readLen(data []byte, off int) (int, int, error) {
    if off >= len(data) { return 0, 0, fmt.Errorf("missing len") }
    first := data[off]
    if first < 0x80 { return int(first), 1, nil }
    count := int(first & 0x7F)
    if count == 0 || off+count > len(data) { return 0, 0, fmt.Errorf("bad long len") }
    var length int
    for i := 0; i < count; i++ {
        length = (length << 8) | int(data[off+1+i])
    }
    return length, 1 + count, nil
}

func binaryFromBytes(b []byte) int {
    var v int
    for _, x := range b { v = (v << 8) | int(x) }
    return v
}

func init() {
    log.SetFlags(0)
    log.SetPrefix("[paia-ldap-proxy] ")
}
