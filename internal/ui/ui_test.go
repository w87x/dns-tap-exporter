package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/w87x/dns-tap-exporter/internal/collector"
	"github.com/w87x/dns-tap-exporter/internal/history"
)

func server(t *testing.T) *httptest.Server {
	t.Helper()
	rec := history.New(time.Hour, time.Minute)
	rec.Add(collector.View{Time: time.Now().Add(-2 * time.Minute), QPS: 7})
	rec.Add(collector.View{Time: time.Now().Add(-30 * time.Minute), QPS: 1}) // older than the 10m range used below
	mux := http.NewServeMux()
	Register(mux, rec, func() collector.View { return collector.View{QPS: 42} }, time.Hour)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return r, sb.String()
}

func TestRoutes(t *testing.T) {
	s := server(t)
	if r, _ := get(t, s.URL+"/"); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/ui/" {
		t.Errorf("/ should redirect to /ui/: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	r, body := get(t, s.URL+"/ui/")
	if r.StatusCode != 200 || !strings.Contains(body, "DNS Tap") || r.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("/ui/: %d csp=%q", r.StatusCode, r.Header.Get("Content-Security-Policy"))
	}
	if r, body := get(t, s.URL+"/ui/app.js"); r.StatusCode != 200 || !strings.Contains(body, "textContent") {
		t.Errorf("app.js not served: %d", r.StatusCode)
	}
	if r, _ := get(t, s.URL+"/no/such/page"); r.StatusCode != 404 {
		t.Errorf("unknown path should 404, got %d", r.StatusCode)
	}
}

func TestAPI(t *testing.T) {
	s := server(t)
	_, body := get(t, s.URL+"/api/now")
	var v collector.View
	if err := json.Unmarshal([]byte(body), &v); err != nil || v.QPS != 42 {
		t.Fatalf("now: %v %q", err, body)
	}
	_, body = get(t, s.URL+"/api/history?range=10m")
	var h struct {
		Interval float64          `json:"interval_sec"`
		Points   []collector.View `json:"points"`
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil || h.Interval != 60 || len(h.Points) != 1 || h.Points[0].QPS != 7 {
		t.Fatalf("history 10m: %v %+v", err, h)
	}
	if r, _ := get(t, s.URL+"/api/history?range=bogus"); r.StatusCode != 400 {
		t.Errorf("bad range should 400, got %d", r.StatusCode)
	}
	_, body = get(t, s.URL+"/api/history?range=1m")
	if !strings.Contains(body, `"points":[]`) {
		t.Errorf("empty history must serialize as [], got %q", body)
	}
}
