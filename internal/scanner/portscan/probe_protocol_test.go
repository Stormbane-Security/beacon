package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestProbeMySQLGreeting — mock MySQL server sends a greeting packet with
// version 5.7.39, auth plugin mysql_native_password, connection ID 42, and
// character set 0x21 (utf8_general_ci).
// ---------------------------------------------------------------------------

func TestProbeMySQLGreeting(t *testing.T) {
	// Build a MySQL greeting packet.
	// Wire format: 3-byte length LE + 1-byte seq (0) + payload
	// Payload:
	//   protocol_version (1: 0x0a)
	//   version string NUL-terminated
	//   connection_id (4 LE)
	//   auth_data_1 (8 bytes)
	//   filler (1 byte, 0x00)
	//   capability_flags_lo (2 LE)
	//   character_set (1)
	//   status_flags (2)
	//   capability_flags_hi (2 LE)
	//   auth_data_len (1) — total length of auth data (plugin data)
	//   reserved (10 bytes, 0x00)
	//   auth_data_2 (max(13, auth_data_len-8) bytes)
	//   auth_plugin_name NUL-terminated

	version := "5.7.39"
	authPlugin := "mysql_native_password"
	connID := uint32(42)
	charSet := byte(0x21) // utf8_general_ci

	var payload bytes.Buffer
	payload.WriteByte(0x0a) // protocol version
	payload.WriteString(version)
	payload.WriteByte(0x00) // NUL terminator

	// connection_id (4 LE)
	idBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(idBuf, connID)
	payload.Write(idBuf)

	// auth_data_1 (8 random bytes)
	payload.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// filler
	payload.WriteByte(0x00)

	// capability_flags_lo (2 LE) — CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
	capsLo := uint16(0x0a0f)
	_ = binary.Write(&payload, binary.LittleEndian, capsLo)

	// character_set
	payload.WriteByte(charSet)

	// status_flags (2)
	payload.Write([]byte{0x02, 0x00})

	// capability_flags_hi (2 LE)
	capsHi := uint16(0x00ff)
	_ = binary.Write(&payload, binary.LittleEndian, capsHi)

	// auth_data_len — total length of auth plugin data
	authDataLen := byte(21) // 8 (part1) + 13 (part2)
	payload.WriteByte(authDataLen)

	// reserved (10 bytes)
	payload.Write(make([]byte, 10))

	// auth_data_2 (13 bytes)
	payload.Write([]byte{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x00})

	// auth_plugin_name NUL-terminated
	payload.WriteString(authPlugin)
	payload.WriteByte(0x00)

	payloadBytes := payload.Bytes()
	pktLen := len(payloadBytes)
	pkt := make([]byte, 4+pktLen)
	pkt[0] = byte(pktLen)
	pkt[1] = byte(pktLen >> 8)
	pkt[2] = byte(pktLen >> 16)
	pkt[3] = 0x00 // sequence number
	copy(pkt[4:], payloadBytes)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(pkt)
		// Keep connection open until client disconnects.
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
	}()

	info := probeMySQLGreeting(context.Background(), "127.0.0.1", port)
	_ = ln.Close()
	<-done

	if info == nil {
		t.Fatal("probeMySQLGreeting returned nil")
	}
	if info.Version != version {
		t.Errorf("Version = %q; want %q", info.Version, version)
	}
	if info.AuthPlugin != authPlugin {
		t.Errorf("AuthPlugin = %q; want %q", info.AuthPlugin, authPlugin)
	}
	if info.ConnectionID != connID {
		t.Errorf("ConnectionID = %d; want %d", info.ConnectionID, connID)
	}
	if info.CharacterSet != charSet {
		t.Errorf("CharacterSet = 0x%02x; want 0x%02x", info.CharacterSet, charSet)
	}
	wantCaps := uint32(capsLo) | uint32(capsHi)<<16
	if info.Capabilities != wantCaps {
		t.Errorf("Capabilities = 0x%08x; want 0x%08x", info.Capabilities, wantCaps)
	}
}

// ---------------------------------------------------------------------------
// TestProbeMSSQLPrelogin — mock TDS prelogin server responds with version
// 15.0.4123 (SQL Server 2019), encryption=on, instance name "MSSQLSERVER".
// ---------------------------------------------------------------------------

func TestProbeMSSQLPrelogin(t *testing.T) {
	wantMajor := byte(15)
	wantMinor := byte(0)
	wantBuild := uint16(4123)
	wantEncryption := byte(1) // on
	wantInstance := "MSSQLSERVER"

	// Build TDS prelogin response payload.
	// Option tokens: VERSION(0x00), ENCRYPTION(0x01), INSTOPT(0x02), terminator(0xFF)
	// Each token: type(1) + offset(2 BE) + length(2 BE)
	// We have 3 tokens × 5 bytes = 15, plus terminator = 16 bytes of header.
	// Then data: VERSION(6) + ENCRYPTION(1) + INSTOPT(len+1 NUL)
	instBytes := append([]byte(wantInstance), 0x00)
	headerLen := 16 // 3 tokens * 5 + 1 terminator
	versionOff := headerLen
	encOff := versionOff + 6
	instOff := encOff + 1
	dataLen := 6 + 1 + len(instBytes)
	payloadLen := headerLen + dataLen

	payload := make([]byte, payloadLen)
	// VERSION token
	payload[0] = 0x00
	payload[1] = byte(versionOff >> 8)
	payload[2] = byte(versionOff)
	payload[3] = 0x00
	payload[4] = 0x06
	// ENCRYPTION token
	payload[5] = 0x01
	payload[6] = byte(encOff >> 8)
	payload[7] = byte(encOff)
	payload[8] = 0x00
	payload[9] = 0x01
	// INSTOPT token
	payload[10] = 0x02
	payload[11] = byte(instOff >> 8)
	payload[12] = byte(instOff)
	payload[13] = byte(len(instBytes) >> 8)
	payload[14] = byte(len(instBytes))
	// Terminator
	payload[15] = 0xFF

	// VERSION data: major, minor, build (BE), sub-build (2 bytes)
	payload[versionOff] = wantMajor
	payload[versionOff+1] = wantMinor
	payload[versionOff+2] = byte(wantBuild >> 8)
	payload[versionOff+3] = byte(wantBuild)
	payload[versionOff+4] = 0x00
	payload[versionOff+5] = 0x00

	// ENCRYPTION data
	payload[encOff] = wantEncryption

	// INSTOPT data
	copy(payload[instOff:], instBytes)

	// Build TDS packet: header(8) + payload
	totalLen := 8 + payloadLen
	tdsPkt := make([]byte, totalLen)
	tdsPkt[0] = 0x04 // PRELOGIN response
	tdsPkt[1] = 0x01 // EOM
	tdsPkt[2] = byte(totalLen >> 8)
	tdsPkt[3] = byte(totalLen)
	tdsPkt[4] = 0x00 // SPID
	tdsPkt[5] = 0x00
	tdsPkt[6] = 0x01 // PacketID
	tdsPkt[7] = 0x00 // Window
	copy(tdsPkt[8:], payload)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// Read the client's prelogin request.
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		// Send our response.
		_, _ = conn.Write(tdsPkt)
	}()

	info := probeMSSQLPrelogin(context.Background(), "127.0.0.1", port)
	_ = ln.Close()
	<-done

	if info == nil {
		t.Fatal("probeMSSQLPrelogin returned nil")
	}
	if info.MajorVersion != wantMajor {
		t.Errorf("MajorVersion = %d; want %d", info.MajorVersion, wantMajor)
	}
	if info.MinorVersion != wantMinor {
		t.Errorf("MinorVersion = %d; want %d", info.MinorVersion, wantMinor)
	}
	if info.BuildNumber != wantBuild {
		t.Errorf("BuildNumber = %d; want %d", info.BuildNumber, wantBuild)
	}
	if info.Encryption != wantEncryption {
		t.Errorf("Encryption = %d; want %d", info.Encryption, wantEncryption)
	}
	if info.InstanceName != wantInstance {
		t.Errorf("InstanceName = %q; want %q", info.InstanceName, wantInstance)
	}
}

// ---------------------------------------------------------------------------
// TestProbeCassandraCQLInfo — mock CQL server responds to OPTIONS with
// CQL_VERSION=3.4.5 and COMPRESSION=snappy,lz4, then to STARTUP with READY
// (no auth required).
// ---------------------------------------------------------------------------

func TestProbeCassandraCQLInfo(t *testing.T) {
	// Build CQL v4 SUPPORTED response body: string multimap.
	// Format: [short n_keys] then for each key: [short key_len][key][short n_values]([short val_len][val])*
	var body bytes.Buffer
	writeShort := func(v int) {
		body.WriteByte(byte(v >> 8))
		body.WriteByte(byte(v))
	}
	writeString := func(s string) {
		writeShort(len(s))
		body.WriteString(s)
	}

	writeShort(2) // 2 keys

	// CQL_VERSION
	writeString("CQL_VERSION")
	writeShort(1)       // 1 value
	writeString("3.4.5") //nolint:goconst

	// COMPRESSION
	writeString("COMPRESSION")
	writeShort(2) // 2 values
	writeString("snappy")
	writeString("lz4")

	supportedBody := body.Bytes()

	// Build CQL v4 SUPPORTED frame: version=0x84, flags=0, stream=0, opcode=0x06, length
	supportedFrame := make([]byte, 9+len(supportedBody))
	supportedFrame[0] = 0x84 // v4 response
	supportedFrame[1] = 0x00
	supportedFrame[2] = 0x00
	supportedFrame[3] = 0x00
	supportedFrame[4] = 0x06 // SUPPORTED
	supportedFrame[5] = byte(len(supportedBody) >> 24)
	supportedFrame[6] = byte(len(supportedBody) >> 16)
	supportedFrame[7] = byte(len(supportedBody) >> 8)
	supportedFrame[8] = byte(len(supportedBody))
	copy(supportedFrame[9:], supportedBody)

	// Build READY response (no auth required): opcode=0x02, empty body
	readyFrame := []byte{
		0x84, // v4 response
		0x00,
		0x00, 0x01, // stream=1
		0x02,                   // READY
		0x00, 0x00, 0x00, 0x00, // body length = 0
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read OPTIONS request (9 bytes).
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)

		// Send SUPPORTED response.
		_, _ = conn.Write(supportedFrame)

		// Read STARTUP request.
		_, _ = conn.Read(buf)

		// Send READY response (no auth).
		_, _ = conn.Write(readyFrame)
	}()

	info := probeCassandraCQLInfo(context.Background(), "127.0.0.1", port)
	_ = ln.Close()
	<-done

	if info == nil {
		t.Fatal("probeCassandraCQLInfo returned nil")
	}
	if len(info.CQLVersions) != 1 || info.CQLVersions[0] != "3.4.5" {
		t.Errorf("CQLVersions = %v; want [3.4.5]", info.CQLVersions)
	}
	if len(info.Compression) != 2 {
		t.Errorf("Compression = %v; want [snappy lz4]", info.Compression)
	} else {
		if info.Compression[0] != "snappy" {
			t.Errorf("Compression[0] = %q; want snappy", info.Compression[0])
		}
		if info.Compression[1] != "lz4" {
			t.Errorf("Compression[1] = %q; want lz4", info.Compression[1])
		}
	}
	if !info.NoAuth {
		t.Error("NoAuth = false; want true (server responded with READY, not AUTHENTICATE)")
	}
}

// ---------------------------------------------------------------------------
// TestProbeSMTPEHLO — mock SMTP server sends greeting, responds to EHLO with
// capabilities, and responds to VRFY with 252.
// ---------------------------------------------------------------------------

func TestProbeSMTPEHLO(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		// Send greeting.
		_, _ = fmt.Fprintf(conn, "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")

		buf := make([]byte, 2048)

		// Read EHLO.
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(string(buf[:n])))
		if strings.HasPrefix(cmd, "EHLO") {
			_, _ = fmt.Fprintf(conn, "250-mail.example.com\r\n"+
				"250-STARTTLS\r\n"+
				"250-AUTH PLAIN LOGIN\r\n"+
				"250-SIZE 10485760\r\n"+
				"250-8BITMIME\r\n"+
				"250 VRFY\r\n")
		}

		// Read VRFY (the probe tests VRFY even if advertised, but code may
		// skip active VRFY test since VRFY was in EHLO caps — read next command anyway).
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		cmd = strings.ToUpper(strings.TrimSpace(string(buf[:n])))
		if strings.HasPrefix(cmd, "VRFY") {
			_, _ = fmt.Fprintf(conn, "252 2.0.0 root\r\n")
			// Read QUIT.
			n, _ = conn.Read(buf)
		}
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(buf[:n]))), "QUIT") {
			_, _ = fmt.Fprintf(conn, "221 Bye\r\n")
		}
	}()

	info := probeSMTPEHLO(context.Background(), "127.0.0.1", port)
	_ = ln.Close()
	<-done

	if info == nil {
		t.Fatal("probeSMTPEHLO returned nil")
	}
	if info.Software != "Postfix" {
		t.Errorf("Software = %q; want %q", info.Software, "Postfix")
	}
	if !info.STARTTLS {
		t.Error("STARTTLS = false; want true")
	}
	if !info.Auth {
		t.Error("Auth = false; want true")
	}
	if len(info.AuthMethods) < 2 {
		t.Errorf("AuthMethods = %v; want at least [PLAIN LOGIN]", info.AuthMethods)
	} else {
		if info.AuthMethods[0] != "PLAIN" {
			t.Errorf("AuthMethods[0] = %q; want PLAIN", info.AuthMethods[0])
		}
		if info.AuthMethods[1] != "LOGIN" {
			t.Errorf("AuthMethods[1] = %q; want LOGIN", info.AuthMethods[1])
		}
	}
	if !info.VRFY {
		t.Error("VRFY = false; want true")
	}
	if info.Size != "10485760" {
		t.Errorf("Size = %q; want %q", info.Size, "10485760")
	}
	if !info.EightBitMIME {
		t.Error("EightBitMIME = false; want true")
	}
	if !strings.Contains(info.Banner, "Postfix") {
		t.Errorf("Banner = %q; want to contain Postfix", info.Banner)
	}
}

// ---------------------------------------------------------------------------
// TestProbeFTPDetails — mock FTP server sends greeting, responds to FEAT
// with a feature list, and allows anonymous login.
// ---------------------------------------------------------------------------

func TestProbeFTPDetails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		// Send FTP banner.
		_, _ = fmt.Fprintf(conn, "220 ProFTPD 1.3.5e Server ready\r\n")

		buf := make([]byte, 2048)

		// Read FEAT command.
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(string(buf[:n])))
		if strings.HasPrefix(cmd, "FEAT") {
			_, _ = fmt.Fprintf(conn, "211-Features:\r\n"+
				" UTF8\r\n"+
				" MLST size*;modify*;perm*;\r\n"+
				" MDTM\r\n"+
				" SIZE\r\n"+
				"211 End\r\n")
		}

		// Read USER anonymous.
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		cmd = strings.ToUpper(strings.TrimSpace(string(buf[:n])))
		if strings.HasPrefix(cmd, "USER") {
			_, _ = fmt.Fprintf(conn, "331 Anonymous login ok, send your email address as your password\r\n")
		}

		// Read PASS.
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		cmd = strings.ToUpper(strings.TrimSpace(string(buf[:n])))
		if strings.HasPrefix(cmd, "PASS") {
			_, _ = fmt.Fprintf(conn, "230 Login successful\r\n")
		}
	}()

	info := probeFTPDetails(context.Background(), "127.0.0.1", port)
	_ = ln.Close()
	<-done

	if info == nil {
		t.Fatal("probeFTPDetails returned nil")
	}
	if !strings.Contains(info.Software, "ProFTPD") {
		t.Errorf("Software = %q; want to contain ProFTPD", info.Software)
	}
	if !strings.Contains(info.Software, "1.3.5e") {
		t.Errorf("Software = %q; want to contain 1.3.5e", info.Software)
	}
	if len(info.Features) == 0 {
		t.Error("Features is empty; want non-empty feature list")
	} else {
		feats := strings.Join(info.Features, "|")
		for _, want := range []string{"UTF8", "MLST", "MDTM", "SIZE"} {
			if !strings.Contains(feats, want) {
				t.Errorf("Features %v missing %q", info.Features, want)
			}
		}
	}
	if !info.Anonymous {
		t.Error("Anonymous = false; want true")
	}
}
