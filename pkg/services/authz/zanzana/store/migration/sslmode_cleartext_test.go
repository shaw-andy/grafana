package migration

import (
	"context"
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

	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	passwordPlaceholder = "placeholder-not-a-secret"
	probeMarker         = "grafana-cleartext-probe"
	postgresSSLRequest  = 80877103
)

func TestOpenFGAPostgresURLDoesNotOpenCleartextSession(t *testing.T) {
	// constructPostgresConnStrForOpenFGA copies the SQL store ssl_mode into the
	// URL goose opens with pgx. The same rule as the SQL store: no cleartext
	// database protocol, and no dial before configuration is refused.
	t.Run("shipped sql store config", func(t *testing.T) {
		addr, rec := listenPostgres(t)
		cfg := shippedDatabaseConfig(t, addr)
		dbCfg, err := sqlstore.NewDatabaseConfig(cfg, nil)
		if err != nil {
			require.Zero(t, rec.connections(), "refusing the database configuration opened a connection first")
			return
		}
		exercisePGX(t, rec, constructPostgresConnStrForOpenFGA(dbCfg))
	})

	t.Run("connection string without sslmode", func(t *testing.T) {
		// The parser branch defaults sslmode when the keyword string has none.
		addr, rec := listenPostgres(t)
		host, port, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		dbCfg := &sqlstore.DatabaseConfig{
			ConnectionString: fmt.Sprintf("user=grafana password=%s host=%s port=%s dbname=grafana", passwordPlaceholder, host, port),
		}
		exercisePGX(t, rec, constructPostgresConnStrForOpenFGA(dbCfg))
	})
}

func exercisePGX(t *testing.T, rec *wireRecord, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err == nil {
		t.Cleanup(func() { _ = conn.Close(ctx) })
		_, _ = conn.Query(ctx, "SELECT '"+probeMarker+"'")
	}
	if rec.cleartextSession() {
		t.Fatalf("cleartext database session (password bytes on wire: %v, probe query on wire: %v)",
			rec.contains(passwordPlaceholder), rec.contains(probeMarker))
	}
	require.Greater(t, rec.connections(), 0, "driver did not connect and configuration was accepted")
}

func shippedDatabaseConfig(t *testing.T, addr string) *setting.Cfg {
	t.Helper()
	parsed, err := ini.Load("../../../../../../conf/defaults.ini")
	require.NoError(t, err)
	sec := parsed.Section("database")
	sec.Key("type").SetValue("postgres")
	sec.Key("host").SetValue(addr)
	sec.Key("user").SetValue("grafana")
	sec.Key("password").SetValue(passwordPlaceholder)
	sec.Key("name").SetValue("grafana")
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
	needle := []byte(s)
	if len(needle) == 0 || len(w.clear) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(w.clear); i++ {
		match := true
		for j := range needle {
			if w.clear[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func listenPostgres(t *testing.T) (string, *wireRecord) {
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
		_, _ = conn.Write([]byte{'N'})
		return
	}
	rec.addClear(append(append([]byte{}, lenBuf[:]...), body...))
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

func readN(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
