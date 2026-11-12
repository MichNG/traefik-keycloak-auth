package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenerateVerifyRoundTrip(t *testing.T) {
	p := New("MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ", time.Hour)

	token, err := p.Generate("session-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !p.Verify(token, "session-1") {
		t.Fatal("a freshly generated token must verify")
	}
	if p.Verify(token, "session-2") {
		t.Fatal("a token bound to another session must not verify")
	}
	if p.Verify(token+"x", "session-1") {
		t.Fatal("a tampered token must not verify")
	}
	if p.Verify("garbage", "session-1") {
		t.Fatal("a malformed token must not verify")
	}
}

func TestTokensAreUnique(t *testing.T) {
	p := New("MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ", time.Hour)

	first, _ := p.Generate("s")
	second, _ := p.Generate("s")
	if first == second {
		t.Fatal("two generated tokens must differ")
	}
}

func TestValidateDoubleSubmit(t *testing.T) {
	p := New("MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ", time.Hour)
	cfg := Config{HeaderName: "Hub-Csrf-Token"}

	token, err := p.Generate("session-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: token})
	req.Header.Set("Hub-Csrf-Token", token)

	if err := p.Validate(cfg, req, "session-1"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	p := New("MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ", time.Hour)
	cfg := Config{}

	token, _ := p.Generate("session-1")

	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"no cookie", func(r *http.Request) { r.Header.Set(DefaultHeaderName, token) }},
		{"no header", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: token}) }},
		{"header mismatch", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: token})
			r.Header.Set(DefaultHeaderName, "other")
		}},
		{"wrong session", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: token})
			r.Header.Set(DefaultHeaderName, token)
		}},
	}

	for i, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		tc.mutate(req)
		binding := "session-1"
		if tc.name == "wrong session" {
			binding = "session-9"
		}
		if err := p.Validate(cfg, req, binding); err == nil {
			t.Errorf("case %d (%s): expected a rejection", i, tc.name)
		}
	}
}

func TestEnsureCookieIssuesOnlyWhenNeeded(t *testing.T) {
	p := New("MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ", time.Hour)
	cfg := Config{Secure: true}

	// First call issues a cookie.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	p.EnsureCookie(cfg, rw, req, "s1")

	res := rw.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	if cookies[0].Name != DefaultCookieName || cookies[0].Value == "" {
		t.Fatalf("unexpected cookie: %+v", cookies[0])
	}
	if !cookies[0].Secure {
		t.Fatal("the Secure flag must be propagated")
	}

	// Second call with a valid cookie issues nothing.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookies[0].Value})
	rw2 := httptest.NewRecorder()
	p.EnsureCookie(cfg, rw2, req2, "s1")

	if len(rw2.Result().Cookies()) != 0 {
		t.Fatal("a valid cookie must not be reissued")
	}
}

func TestIsSafeMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		if !IsSafeMethod(m) {
			t.Errorf("%s must be safe", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if IsSafeMethod(m) {
			t.Errorf("%s must not be safe", m)
		}
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	p := New("MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ", time.Millisecond)

	token, err := p.Generate("s")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	if p.Verify(token, "s") {
		t.Fatal("a token older than the TTL must not verify")
	}
}
