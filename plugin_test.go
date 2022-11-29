package jc2h_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aseara/jc2h"
	"github.com/golang-jwt/jwt/v4"
)

func TestEmptyConfig(t *testing.T) {
	cfg := jc2h.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jc2h.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
}

func TestHeaderCheck1(t *testing.T) {
	cfg := jc2h.CreateConfig()
	cfg.CheckHeader = true

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := jc2h.New(ctx, next, cfg, "demo-plugin")
	// need ssoLoginUrl
	if err == nil {
		t.Fatal("expect an error")
	}
	cfg.SsoLoginURL = "https://sso.xxxx.com"

	_, err = jc2h.New(ctx, next, cfg, "demo-plugin")
	// need signKey
	if err == nil {
		t.Fatal("expect an error")
	}
	kd, _ := os.ReadFile("test/sample_key.pub")
	cfg.SignKey = string(kd)

	handler, err := jc2h.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("http code should be %v but get %v", http.StatusTemporaryRedirect, recorder.Code)
	}

	assertHeader(t, recorder, "Location", "https://eop-sso.mh3cloud.cn?ReturnUrl=http://localhost")
}

func TestHeaderCheck2(t *testing.T) {
	cfg := jc2h.CreateConfig()
	cfg.CheckHeader = true
	cfg.SsoLoginURL = "https://sso.xxxx.com"
	kd, _ := os.ReadFile("test/sample_key.pub")
	cfg.SignKey = string(kd)
	cfg.InjectHeader = "X-JWT-TOKEN"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jc2h.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	token := createToken()
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("http code should be %v but get %v", http.StatusOK, recorder.Code)
	}

	assertReqHeader(t, req, cfg.InjectHeader, token)
}

func TestCookieCheck(t *testing.T) {
	cfg := jc2h.CreateConfig()
	cfg.CheckCookie = true
	cfg.CookieName = "jwt-token"
	cfg.SsoLoginURL = "https://sso.xxxx.com"
	kd, _ := os.ReadFile("test/sample_key.pub")
	cfg.SignKey = string(kd)
	cfg.InjectHeader = "X-JWT-TOKEN"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jc2h.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	token := createToken()
	cookie := &http.Cookie{
		Name:   cfg.CookieName,
		Value:  token,
		MaxAge: 300,
	}

	req.AddCookie(cookie)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("http code should be %v but get %v", http.StatusOK, recorder.Code)
	}

	assertReqHeader(t, req, cfg.InjectHeader, token)
}

func createToken() string {
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
			jwt.RegisteredClaims
		}{
			Name: "aseara",
			ID:   12306,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-1000 * time.Second)),
				ID:        strconv.Itoa(12306),
				Issuer:    "sso.mh3cloud.cn",
			},
		},
	)

	kd, _ := os.ReadFile("test/sample_key")
	k, _ := jwt.ParseRSAPrivateKeyFromPEM(kd)
	j, _ := token.SignedString(k)
	return j
}

func assertHeader(t *testing.T, recorder *httptest.ResponseRecorder, key, expected string) {
	t.Helper()

	if recorder.Header().Get(key) != expected {
		t.Errorf("invalid header value: [%s] %s", key, recorder.Header().Get(key))
	}
}

func assertReqHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: [%s] %s", key, req.Header.Get(key))
	}
}
