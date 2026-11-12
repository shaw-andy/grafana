package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContext_RemoteAddr(t *testing.T) {
	_, proxyNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*net.IPNet{proxyNet}

	tests := []struct {
		name    string
		trusted []*net.IPNet
		header  string
		req     *http.Request
		want    string
	}{
		{
			name: "Untrusted peer with X-Real-Ip should return the peer",
			req: &http.Request{
				RemoteAddr: "255.255.255.255",
				Header: http.Header{
					"X-Real-Ip": []string{"192.168.1.1"},
				},
			},
			want: "255.255.255.255",
		},
		{
			name: "Untrusted peer with X-Forwarded-For should return the peer",
			req: &http.Request{
				RemoteAddr: "203.0.113.10:4242",
				Header: http.Header{
					"X-Forwarded-For": []string{"192.168.1.1, 203.0.113.10"},
				},
			},
			want: "203.0.113.10",
		},
		{
			name:    "Peer outside the trusted proxies should return the peer",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "203.0.113.10:4242",
				Header: http.Header{
					"X-Forwarded-For": []string{"192.168.1.1"},
				},
			},
			want: "203.0.113.10",
		},
		{
			name:    "Trusted proxy should return the rightmost untrusted X-Forwarded-For address",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Forwarded-For": []string{"198.51.100.1, 192.168.1.1, 10.0.0.3"},
				},
			},
			want: "192.168.1.1",
		},
		{
			name:    "Trusted proxy should read X-Forwarded-For across repeated headers",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Forwarded-For": []string{"198.51.100.1", "192.168.1.1"},
				},
			},
			want: "192.168.1.1",
		},
		{
			name:    "Trusted proxy should ignore X-Real-Ip when X-Forwarded-For is configured",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Real-Ip":       []string{"198.51.100.1"},
					"X-Forwarded-For": []string{"192.168.1.1"},
				},
			},
			want: "192.168.1.1",
		},
		{
			name:    "Trusted proxy with an invalid X-Forwarded-For entry should stop at the last valid hop",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Forwarded-For": []string{"192.168.1.1, not an ip, 10.0.0.3"},
				},
			},
			want: "10.0.0.3",
		},
		{
			name:    "Trusted proxy without forwarding headers should return the peer",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header:     http.Header{},
			},
			want: "10.0.0.2",
		},
		{
			name:    "Trusted proxy should return IPv6 addresses from X-Forwarded-For",
			trusted: trusted,
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Forwarded-For": []string{"2001:db8:85a3:8d3:1319:8a2e:370:7348"},
				},
			},
			want: "2001:db8:85a3:8d3:1319:8a2e:370:7348",
		},
		{
			name:    "Trusted proxy with a configured header should return its value",
			trusted: trusted,
			header:  "x-real-ip",
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Real-Ip":       []string{"192.168.1.1"},
					"X-Forwarded-For": []string{"198.51.100.1"},
				},
			},
			want: "192.168.1.1",
		},
		{
			name:    "Trusted proxy with an invalid configured header should return the peer",
			trusted: trusted,
			header:  "X-Real-Ip",
			req: &http.Request{
				RemoteAddr: "10.0.0.2:4242",
				Header: http.Header{
					"X-Real-Ip":       []string{"this is not a valid IP"},
					"X-Forwarded-For": []string{"192.168.1.1"},
				},
			},
			want: "10.0.0.2",
		},
		{
			name: "When no header is informed, should return remote_addr without port",
			req: &http.Request{
				RemoteAddr: "[::1]:51299",
				Header:     http.Header{},
			},
			want: "[::1]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxies(tt.trusted, tt.header)
			t.Cleanup(func() { SetTrustedProxies(nil, "") })

			ctx := &Context{
				Req: tt.req,
			}
			if got := ctx.RemoteAddr(); got != tt.want {
				t.Errorf("RemoteAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContext_noHandler(t *testing.T) {
	recorder := httptest.NewRecorder()

	method := http.MethodGet
	c := &Context{
		Req:  httptest.NewRequest(method, "/", nil),
		Resp: NewResponseWriter(method, recorder),
	}

	c.run()

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
}
