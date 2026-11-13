package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/setting"
)

// passwordPlaceholder is an obvious stand-in for the database password.
// The wire capture is checked for these bytes and is never printed.
const passwordPlaceholder = "placeholder-not-a-secret"

// probeMarker is the text of the query issued after authentication.
const probeMarker = "grafana-cleartext-probe"

// postgresSSLRequest is the 4-byte code lib/pq and pgx write before a TLS handshake
// (lib/pq proto.NegotiateSSLCode, pgx startTLS).
const postgresSSLRequest = 80877103

func TestShippedSSLModeDoesNotOpenCleartextSession(t *testing.T) {
	// Operators who select postgres or mysql and leave ssl_mode at the shipped
	// value must not get a database session whose protocol bytes are readable
	// on the network. Refusing to build the config, before any dial, also
	// satisfies that. A TLS attempt that falls back to the cleartext protocol
	// does not.
	cases := []struct {
		name    string
		dialect string
		driver  string
		url     bool
		// setSSLMode overwrites the shipped value. Empty leaves the file untouched.
		setSSLMode string
	}{
		{name: "postgres libpq shipped ssl_mode", dialect: "postgres", driver: "postgres"},
		{name: "postgres libpq ssl_mode disable", dialect: "postgres", driver: "postgres", setSSLMode: "disable"},
		{name: "postgres libpq url shipped ssl_mode", dialect: "postgres", driver: "postgres", url: true},
		{name: "pgx shipped ssl_mode", dialect: "postgres", driver: "pgx"},
		{name: "mysql shipped ssl_mode", dialect: "mysql", driver: "mysql"},
		{name: "mysql ssl_mode disable", dialect: "mysql", driver: "mysql", setSSLMode: "disable"},
		{name: "mysql url shipped ssl_mode", dialect: "mysql", driver: "mysql", url: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, rec := listenDB(t, tc.dialect)
			cfg := shippedDatabaseConfig(t, func(sec *ini.Section) {
				if tc.setSSLMode != "" {
					sec.Key("ssl_mode").SetValue(tc.setSSLMode)
				}
				if tc.url {
					scheme := tc.dialect
					sec.Key("url").SetValue(fmt.Sprintf("%s://grafana:%s@%s/grafana", scheme, passwordPlaceholder, addr))
					return
				}
				sec.Key("type").SetValue(tc.dialect)
				sec.Key("host").SetValue(addr)
				sec.Key("user").SetValue("grafana")
				sec.Key("password").SetValue(passwordPlaceholder)
				sec.Key("name").SetValue("grafana")
			})

			dbCfg, err := NewDatabaseConfig(cfg, nil)
			if err != nil {
				require.Zero(t, rec.connections(), "refusing the database configuration opened a connection first")
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			switch tc.driver {
			case "postgres":
				db, openErr := sql.Open("postgres", dbCfg.ConnectionString)
				require.NoError(t, openErr)
				t.Cleanup(func() { _ = db.Close() })
				db.SetMaxOpenConns(1)
				_, _ = db.QueryContext(ctx, "SELECT '"+probeMarker+"'")
			case "mysql":
				db, openErr := sql.Open("mysql", dbCfg.ConnectionString)
				require.NoError(t, openErr)
				t.Cleanup(func() { _ = db.Close() })
				db.SetMaxOpenConns(1)
				_, _ = db.QueryContext(ctx, "SELECT '"+probeMarker+"'")
			case "pgx":
				conn, connectErr := pgx.Connect(ctx, dbCfg.ConnectionString)
				if connectErr == nil {
					t.Cleanup(func() { _ = conn.Close(ctx) })
					_, _ = conn.Query(ctx, "SELECT '"+probeMarker+"'")
				}
			default:
				t.Fatalf("unknown driver %s", tc.driver)
			}

			if rec.cleartextSession() {
				t.Fatalf("cleartext database session (password bytes on wire: %v, probe query on wire: %v)",
					rec.contains(passwordPlaceholder), rec.contains(probeMarker))
			}
			require.Greater(t, rec.connections(), 0, "driver did not connect and configuration was accepted")
		})
	}
}

func shippedDatabaseConfig(t *testing.T, mutate func(*ini.Section)) *setting.Cfg {
	t.Helper()
	parsed, err := ini.Load("../../../conf/defaults.ini")
	require.NoError(t, err)
	mutate(parsed.Section("database"))
	cfg := setting.NewCfg()
	cfg.Raw = parsed
	return cfg
}

type wireRecord struct {
	mu        sync.Mutex
	conns     int
	clear     []byte
	cleartext bool
}

func (w *wireRecord) addConn() {
	w.mu.Lock()
	w.conns++
	w.mu.Unlock()
}

func (w *wireRecord) connections() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conns
}

func (w *wireRecord) addClear(b []byte) {
	w.mu.Lock()
	w.clear = append(w.clear, b...)
	w.cleartext = true
	w.mu.Unlock()
}

func (w *wireRecord) cleartextSession() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cleartext
}

func (w *wireRecord) contains(s string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Contains(w.clear, []byte(s))
}

func listenDB(t *testing.T, kind string) (string, *wireRecord) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	rec := &wireRecord{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			rec.addConn()
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if kind == "mysql" {
					handleMySQL(c, rec)
					return
				}
				handlePostgres(c, rec)
			}(conn)
		}
	}()
	return ln.Addr().String(), rec
}

func handlePostgres(conn net.Conn, rec *wireRecord) {
	head, err := readN(conn, 1)
	if err != nil {
		return
	}
	if head[0] == 0x16 {
		ver, err := readN(conn, 1)
		if err == nil && ver[0] == 0x03 {
			return
		}
		return
	}
	lenRest, err := readN(conn, 3)
	if err != nil {
		return
	}
	var lenBuf [4]byte
	lenBuf[0] = head[0]
	copy(lenBuf[1:], lenRest)
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	if n < 4 || n > 1<<20 {
		return
	}
	body, err := readN(conn, n-4)
	if err != nil {
		return
	}
	if n == 8 && binary.BigEndian.Uint32(body) == postgresSSLRequest {
		// Decline TLS so a mode that falls back (prefer, allow) still has to
		// show itself. A verifying mode stops here without a startup message.
		_, _ = conn.Write([]byte{'N'})
		return
	}
	rec.addClear(append(append([]byte{}, lenBuf[:]...), body...))

	// AuthenticationCleartextPassword. lib/pq and pgx both write the password
	// bytes in the next message when they receive this.
	_, _ = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})
	if !readFrontendMessage(conn, rec) {
		return
	}
	_, _ = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})
	_, _ = conn.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
	_ = readFrontendMessage(conn, rec)
}

func readFrontendMessage(conn net.Conn, rec *wireRecord) bool {
	hdr, err := readN(conn, 5)
	if err != nil {
		return false
	}
	n := int(binary.BigEndian.Uint32(hdr[1:]))
	if n < 4 || n > 1<<20 {
		return false
	}
	payload, err := readN(conn, n-4)
	if err != nil {
		return false
	}
	rec.addClear(append(hdr, payload...))
	return true
}

func handleMySQL(conn net.Conn, rec *wireRecord) {
	greeting := mysqlGreeting()
	if _, err := conn.Write(greeting); err != nil {
		return
	}
	pkt, err := readMySQLPacket(conn)
	if err != nil {
		return
	}
	if isMySQLSSLRequest(pkt) {
		ver := make([]byte, 2)
		_, err := io.ReadFull(conn, ver)
		if err == nil && ver[0] == 0x16 && ver[1] == 0x03 {
			return
		}
		return
	}
	rec.addClear(pkt)
	if err := writeMySQLOK(conn, pkt[3]+1); err != nil {
		return
	}
	for {
		pkt, err := readMySQLPacket(conn)
		if err != nil {
			return
		}
		rec.addClear(pkt)
		if bytes.Contains(pkt, []byte(probeMarker)) {
			return
		}
		if err := writeMySQLOK(conn, pkt[3]+1); err != nil {
			return
		}
	}
}

func isMySQLSSLRequest(pkt []byte) bool {
	if len(pkt) < 4 {
		return false
	}
	n := int(pkt[0]) | int(pkt[1])<<8 | int(pkt[2])<<16
	// go-sql-driver writes a 32-byte SSL request before the TLS handshake
	// when Config.TLS is set, and the full handshake otherwise.
	return n == 32 && len(pkt) == 36
}

func readMySQLPacket(conn net.Conn) ([]byte, error) {
	hdr, err := readN(conn, 4)
	if err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := readN(conn, n)
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func writeMySQLOK(conn net.Conn, seq byte) error {
	body := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	pkt := []byte{byte(len(body)), 0, 0, seq}
	pkt = append(pkt, body...)
	_, err := conn.Write(pkt)
	return err
}

// mysqlGreeting is a protocol-10 handshake the driver accepts. The payload is the
// one readHandshakePacket is tested against, with the sequence number set to the
// value a new connection expects.
func mysqlGreeting() []byte {
	pkt := []byte{
		72, 0, 0, 0, 10, 53, 46, 53, 46, 56, 0, 165, 0, 0, 0,
		60, 70, 63, 58, 68, 104, 34, 97, 0, 223, 247, 33, 2, 0, 15, 128, 21, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 98, 120, 114, 47, 85, 75, 109, 99, 51, 77,
		50, 64, 0, 109, 121, 115, 113, 108, 95, 110, 97, 116, 105, 118, 101, 95,
		112, 97, 115, 115, 119, 111, 114, 100,
	}
	return pkt
}

func readN(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
