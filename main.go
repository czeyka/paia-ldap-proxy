package main

import (
	"encoding/binary"
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
	ldapMessageSEQUENCE = 0x30
	ldapInteger        = 0x02
	ldapString         = 0x04
	ldapEnum           = 0x0A
	ldapBindRequest    = 0x60
	ldapBindResponse   = 0x61
	ldapSearchRequest  = 0x63
	ldapSearchEntry    = 0x64
	ldapSearchDone     = 0x65

	ldapResultSuccess          = 0
	ldapResultInvalidCreds     = 49
	ldapResultNoSuchObject     = 32
	ldapResultUnwillingToPerform = 53
)

type config struct {
	PAIABaseURL string
	PAIAISIL    string
	PAIAAuthURL string
	PAIACoreURL string
	LDAPListen  string
	LDAPBaseDN  string
}

type paiaPatron struct {
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Address string   `json:"address"`
	Expires string   `json:"expires"`
	Status  int      `json:"status"`
	Type    []string `json:"type"`
	Note    string   `json:"note"`
	Node    string   `json:"node"`
}

type ldapMessage struct {
	id int
	op byte
	payload []byte
}

type ldapAttribute struct {
	Name   string
	Values []string
}

func main() {
	cfg := loadConfig()
	ln, err := net.Listen("tcp", cfg.LDAPListen)
	if err != nil {
		log.Fatalf("listen ldap: %v", err)
	}
	defer ln.Close()
	log.Printf("PAIA LDAP proxy listening on %s", cfg.LDAPListen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, cfg)
	}
}

func loadConfig() config {
	base := strings.TrimRight(os.Getenv("PAIA_BASE_URL"), "/")
	if base == "" {
		base = "https://paia.gbv.de"
	}
	isil := strings.TrimSpace(os.Getenv("PAIA_ISIL"))
	if isil == "" {
		isil = "DE-841"
	}
	authPath := strings.Trim(os.Getenv("PAIA_AUTH_PATH"), "/")
	if authPath == "" {
		authPath = "auth"
	}
	corePath := strings.Trim(os.Getenv("PAIA_CORE_PATH"), "/")
	if corePath == "" {
		corePath = "core"
	}
	ldapListen := os.Getenv("LDAP_LISTEN")
	if ldapListen == "" {
		ldapListen = ":389"
	}
	ldapBaseDN := os.Getenv("LDAP_BASE_DN")
	if ldapBaseDN == "" {
		ldapBaseDN = "dc=library,dc=local"
	}
	return config{
		PAIABaseURL: base,
		PAIAISIL:    isil,
		PAIAAuthURL: strings.TrimRight(base, "/") + "/" + strings.Trim(isil, "/") + "/" + authPath,
		PAIACoreURL: strings.TrimRight(base, "/") + "/" + strings.Trim(isil, "/") + "/" + corePath,
		LDAPListen:  ldapListen,
		LDAPBaseDN:  ldapBaseDN,
	}
}

func handleConn(conn net.Conn, cfg config) {
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("set read deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			log.Printf("read ldap packet: %v", err)
		}
		return
	}
	msg, err := parseLDAPMessage(buf[:n])
	if err != nil {
		log.Printf("parse ldap packet: %v", err)
		_ = sendLDAPResult(conn, 1, ldapBindResponse, ldapResultInvalidCreds, "", "malformed LDAP packet")
		return
	}

	switch msg.op {
	case ldapBindRequest:
		username, password, ok := parseBindRequest(msg.payload)
		if !ok {
			_ = sendLDAPResult(conn, msg.id, ldapBindResponse, ldapResultInvalidCreds, "", "missing credentials")
			return
		}
		patron, err := paiaLoginAndFetchPatron(cfg, username, password)
		if err != nil {
			log.Printf("bind failed for %s: %v", username, err)
			_ = sendLDAPResult(conn, msg.id, ldapBindResponse, ldapResultInvalidCreds, "", err.Error())
			return
		}
		_ = sendLDAPResult(conn, msg.id, ldapBindResponse, ldapResultSuccess, "", "OK")
		_ = sendLDAPSearchEntry(conn, msg.id, patron, cfg)
		_ = sendLDAPDone(conn, msg.id)

	case ldapSearchRequest:
		baseDN := parseSearchBaseDN(msg.payload)
		username := strings.TrimPrefix(baseDN, "uid=")
		if username == "" {
			username = "anonymous"
		}
		if username == "anonymous" {
			_ = sendLDAPDone(conn, msg.id)
			return
		}
		patron, err := paiaLoginAndFetchPatron(cfg, username, "")
		if err != nil {
			_ = sendLDAPResult(conn, msg.id, ldapSearchDone, ldapResultNoSuchObject, "", err.Error())
			return
		}
		_ = sendLDAPSearchEntry(conn, msg.id, patron, cfg)
		_ = sendLDAPDone(conn, msg.id)

	default:
		_ = sendLDAPResult(conn, msg.id, ldapBindResponse, ldapResultUnwillingToPerform, "", "unsupported LDAP operation")
	}
}

func parseLDAPMessage(data []byte) (ldapMessage, error) {
	if len(data) < 2 || data[0] != ldapMessageSEQUENCE {
		return ldapMessage{}, fmt.Errorf("not an LDAP SEQUENCE")
	}
	_, next, err := readASN1Element(data, 0)
	if err != nil {
		return ldapMessage{}, err
	}
	if next > len(data) {
		return ldapMessage{}, fmt.Errorf("truncated LDAP message")
	}
	// message content is: INTEGER messageID + protocolOp
	msgBytes := data[2:next]
	if len(msgBytes) < 2 {
		return ldapMessage{}, fmt.Errorf("too short LDAP message")
	}
	idTag, idValue, pos, err := readASN1Element(msgBytes, 0)
	if err != nil || idTag != ldapInteger {
		return ldapMessage{}, fmt.Errorf("missing message ID")
	}
	msgID := int(binary.BigEndian.Uint32(append([]byte{0, 0, 0, 0}, idValue...)))
	if len(idValue) == 1 {
		msgID = int(idValue[0])
	}
	if pos >= len(msgBytes) {
		return ldapMessage{}, fmt.Errorf("missing protocol op")
	}
	opTag, opValue, _, err := readASN1Element(msgBytes, pos)
	if err != nil {
		return ldapMessage{}, err
	}
	return ldapMessage{id: msgID, op: opTag, payload: opValue}, nil
}

func parseBindRequest(data []byte) (string, string, bool) {
	// BindRequest = SEQUENCE { version INTEGER, name LDAPDN, authentication CHOICE }
	// Here we support simple bind auth.
	if len(data) == 0 {
		return "", "", false
	}
	seqTag, seqValue, _, err := readASN1Element(data, 0)
	if err != nil || seqTag != ldapMessageSEQUENCE {
		return "", "", false
	}
	pos := 0
	_, _, pos, err = readASN1Element(seqValue, pos) // version INTEGER
	if err != nil {
		return "", "", false
	}
	nameTag, nameValue, pos, err := readASN1Element(seqValue, pos)
	if err != nil || nameTag != ldapString {
		return "", "", false
	}
	user := string(nameValue)
	if pos >= len(seqValue) {
		return user, "", false
	}
	authTag, authValue, _, err := readASN1Element(seqValue, pos)
	if err != nil {
		return user, "", false
	}
	if authTag == 0x80 {
		return user, string(authValue), true
	}
	if authTag == ldapString {
		return user, string(authValue), true
	}
	return user, "", false
}

func parseSearchBaseDN(data []byte) string {
	seqTag, seqValue, _, err := readASN1Element(data, 0)
	if err != nil || seqTag != ldapMessageSEQUENCE {
		return ""
	}
	pos := 0
	for pos < len(seqValue) {
		tag, value, next, err := readASN1Element(seqValue, pos)
		if err != nil {
			break
		}
		if tag == ldapString {
			return string(value)
		}
		pos = next
	}
	return ""
}

func paiaLoginAndFetchPatron(cfg config, username, password string) (paiaPatron, error) {
	if strings.TrimSpace(username) == "" {
		return paiaPatron{}, fmt.Errorf("missing username")
	}

	loginURL, err := url.Parse(cfg.PAIAAuthURL + "/login")
	if err != nil {
		return paiaPatron{}, err
	}
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("grant_type", "password")
	form.Set("isil", cfg.PAIAISIL)
	loginReq, err := http.NewRequest(http.MethodPost, loginURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return paiaPatron{}, err
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Accept", "application/json")
	resp, err := httpClient().Do(loginReq)
	if err != nil {
		return paiaPatron{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return paiaPatron{}, fmt.Errorf("PAIA login failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return paiaPatron{}, err
	}
	if token.AccessToken == "" {
		return paiaPatron{}, fmt.Errorf("PAIA login reply missing access_token")
	}

	patronURL := cfg.PAIACoreURL + "/" + url.PathEscape(username)
	patronReq, err := http.NewRequest(http.MethodGet, patronURL, nil)
	if err != nil {
		return paiaPatron{}, err
	}
	patronReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	patronReq.Header.Set("Accept", "application/json")
	patronResp, err := httpClient().Do(patronReq)
	if err != nil {
		return paiaPatron{}, err
	}
	defer patronResp.Body.Close()
	if patronResp.StatusCode < 200 || patronResp.StatusCode >= 300 {
		body, _ := io.ReadAll(patronResp.Body)
		return paiaPatron{}, fmt.Errorf("PAIA patron lookup failed: %s %s", patronResp.Status, strings.TrimSpace(string(body)))
	}
	var patron paiaPatron
	if err := json.NewDecoder(patronResp.Body).Decode(&patron); err != nil {
		return paiaPatron{}, err
	}
	if patron.Name == "" {
		patron.Name = username
	}
	return patron, nil
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func sendLDAPResult(conn net.Conn, msgID int, opTag byte, code int, matchedDN, diagnostic string) error {
	payload := ldapResultPayload(code, matchedDN, diagnostic)
	return writeLDAPMessage(conn, msgID, opTag, payload)
}

func sendLDAPDone(conn net.Conn, msgID int) error {
	return sendLDAPResult(conn, msgID, ldapSearchDone, ldapResultSuccess, "", "")
}

func sendLDAPSearchEntry(conn net.Conn, msgID int, patron paiaPatron, cfg config) error {
	entryDN := "uid=" + patron.Name + "," + cfg.LDAPBaseDN
	attrs := []ldapAttribute{
		{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
		{Name: "uid", Values: []string{patron.Name}},
		{Name: "cn", Values: []string{patron.Name}},
		{Name: "sn", Values: []string{patron.Name}},
		{Name: "mail", Values: []string{patron.Email}},
		{Name: "displayName", Values: []string{patron.Name}},
		{Name: "description", Values: []string{patron.Note}},
		{Name: "accountState", Values: []string{strconv.Itoa(patron.Status)}},
		{Name: "paiaStatus", Values: []string{strconv.Itoa(patron.Status)}},
		{Name: "memberOf", Values: []string{"PAIA"}},
		{Name: "nsAccountLock", Values: []string{boolToLDAPLock(patron.Status)}},
	}
	if patron.Node != "" {
		attrs = append(attrs, ldapAttribute{Name: "departmentNumber", Values: []string{patron.Node}})
	}
	payload := ldapEntryPayload(entryDN, attrs)
	return writeLDAPMessage(conn, msgID, ldapSearchEntry, payload)
}

func boolToLDAPLock(status int) string {
	if status == 0 {
		return "FALSE"
	}
	return "TRUE"
}

func writeLDAPMessage(conn net.Conn, msgID int, opTag byte, payload []byte) error {
	payloadWithHeader := encodeASN1(opTag, payload)
	msg := encodeASN1(ldapMessageSEQUENCE, append(encodeASN1(ldapInteger, encodeInt(msgID)), payloadWithHeader...))
	_, err := conn.Write(msg)
	return err
}

func ldapResultPayload(code int, matchedDN, diagnostic string) []byte {
	seq := encodeASN1(ldapEnum, encodeInt(code))
	seq = append(seq, encodeASN1(ldapString, []byte(matchedDN))...)
	seq = append(seq, encodeASN1(ldapString, []byte(diagnostic))...)
	return encodeASN1(ldapMessageSEQUENCE, seq)
}

func ldapEntryPayload(dn string, attrs []ldapAttribute) []byte {
	// DN is encoded as LDAPString
	entry := encodeASN1(ldapString, []byte(dn))
	attrBlock := []byte{}
	for _, a := range attrs {
		values := []byte{}
		for _, v := range a.Values {
			values = append(values, encodeASN1(ldapString, []byte(v))...)
		}
		valPart := append(encodeASN1(ldapString, []byte(a.Name)), values...)
		attrBlock = append(attrBlock, encodeASN1(ldapMessageSEQUENCE, valPart)...)
	}
	entry = append(entry, encodeASN1(ldapMessageSEQUENCE, attrBlock)...)
	return entry
}

func encodeASN1(tag byte, value []byte) []byte {
	return append([]byte{tag}, append(encodeLength(len(value)), value...)...)
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	buf := make([]byte, 0, 4)
	for length > 0 {
		buf = append([]byte{byte(length & 0xff)}, buf...)
		length >>= 8
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

func encodeInt(i int) []byte {
	if i == 0 {
		return []byte{0x00}
	}
	buf := []byte{}
	for i > 0 {
		buf = append([]byte{byte(i & 0xff)}, buf...)
		i >>= 8
	}
	return buf
}

func readASN1Element(data []byte, pos int) (byte, []byte, int, error) {
	if pos >= len(data) {
		return 0, nil, pos, fmt.Errorf("unexpected end of ASN.1 data")
	}
	tag := data[pos]
	pos++
	if pos >= len(data) {
		return 0, nil, pos, fmt.Errorf("truncated ASN.1 length")
	}
	length, n := readLengthAt(data, pos)
	pos += n
	if pos+length > len(data) {
		return 0, nil, pos, fmt.Errorf("ASN.1 length exceeds remaining bytes")
	}
	value := append([]byte(nil), data[pos:pos+length]...)
	return tag, value, pos + length, nil
}

func readLengthAt(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return 0, 0
	}
	first := data[pos]
	if first < 0x80 {
		return int(first), 1
	}
	count := int(first & 0x7F)
	length := 0
	for i := 0; i < count; i++ {
		if pos+1+i >= len(data) {
			return 0, 1
		}
		length = (length << 8) | int(data[pos+1+i])
	}
	return length, 1 + count
}

func init() {
	log.SetFlags(0)
	log.SetPrefix("[paia-ldap-proxy] ")
}
