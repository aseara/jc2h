// Package jc2h plugin a jwt auth plugin.
package jc2h

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwtv4 "github.com/golang-jwt/jwt/v4"
)

// Config the plugin configuration.
type Config struct {
	CheckCookie       bool   `json:"checkCookie,omitempty"`
	CookieName        string `json:"cookieName,omitempty"`
	CheckHeader       bool   `json:"checkHeader,omitempty"`
	HeaderName        string `json:"headerName,omitempty"`
	HeaderValuePrefix string `json:"headerValuePrefix,omitempty"`
	SignKey           string `json:"signKey,omitempty"`
	SsoLoginURL       string `json:"ssoLoginUrl,omitempty"`
	InjectHeader      string `json:"injectHeader,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// JwtPlugin a JwtPlugin plugin.
type JwtPlugin struct {
	name   string
	config *Config
	next   http.Handler
}

// New created a new JwtPlugin plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.CheckCookie && len(config.CookieName) == 0 {
		return nil, fmt.Errorf("cookieName cannot be empty when checkCookie is true")
	}

	if config.CheckHeader && len(config.HeaderName) == 0 {
		config.HeaderName = "Authorization"
		config.HeaderValuePrefix = "Bearer"
	}

	if (config.CheckHeader || config.CheckCookie) && len(config.SsoLoginURL) == 0 {
		return nil, fmt.Errorf("ssoLoginURL cannot be empty when checkCookie or checkHeader is true")
	}

	if config.CheckHeader || config.CheckCookie {
		if len(config.SignKey) == 0 {
			return nil, fmt.Errorf("signKey cannot be empty when checkCookie or checkHeader is true")
		}
	}

	return &JwtPlugin{
		name:   name,
		config: config,
		next:   next,
	}, nil
}

func (j *JwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Println("jwt.ServeHTTP jwt.name:", j.name)
	log.Println("jwt.ServeHTTP req.URL:", req.URL)
	log.Println("jwt.ServeHTTP.req.Host:", req.Host)
	log.Println("jwt.ServeHTTP.req.RequestURI:", req.RequestURI)
	log.Printf("jwt.ServeHTTP jwt.config: %+v", j.config)

	if !j.config.CheckCookie && !j.config.CheckHeader {
		log.Println("jwt.ServeHTTP no need to check cookie or header, pass through")
		j.next.ServeHTTP(rw, req)
		return
	}

	t := getToken(req, j.config)
	if len(t) == 0 {
		log.Println("jwt.ServeHTTP jwt token is nil")
		redirectToLogin(j.config, rw, req)
		return
	}

	if _, err := jwtv4.ParseRSAPublicKeyFromPEM([]byte(j.config.SignKey)); err != nil {
		log.Println("jwt.ServeHTTP parse pk error:", err)
	}

	err := checkToken(t, j.config.SignKey)
	if err != nil {
		log.Println("jwt.ServeHTTP token valid false", err)
		redirectToLogin(j.config, rw, req)
		return
	}

	if len(j.config.InjectHeader) != 0 {
		req.Header.Set(j.config.InjectHeader, t)
	}

	log.Println("jwt.ServeHTTP success")
	j.next.ServeHTTP(rw, req)
}

func getToken(req *http.Request, c *Config) string {
	var t string

	if c.CheckCookie {
		if c, err := req.Cookie(c.CookieName); err == nil {
			t = c.Value
		}
	}

	if len(t) == 0 && c.CheckHeader {
		t = req.Header.Get(c.HeaderName)
		if len(t) != 0 && len(c.HeaderValuePrefix) != 0 {
			t = strings.TrimPrefix(t, c.HeaderValuePrefix)
		}
	}

	if len(t) != 0 {
		t = strings.TrimSpace(t)
	}
	return t
}

func redirectToLogin(c *Config, rw http.ResponseWriter, req *http.Request) {
	var b strings.Builder
	b.WriteString(c.SsoLoginURL)
	b.WriteString("?ReturnUrl=https://")
	b.WriteString(req.Host)
	b.WriteString(req.RequestURI)

	location := b.String()
	log.Println("jwt.ServeHTTP redirect to:", location)

	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusTemporaryRedirect)
	msg := fmt.Sprintf("%s to: %s", http.StatusText(http.StatusTemporaryRedirect), location)
	_, err := rw.Write([]byte(msg))
	if err != nil {
		log.Println("jwt.ServeHTTP redirect err:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

type jwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}

type jwt struct {
	Plaintext []byte
	Signature []byte
	Header    jwtHeader
	Payload   map[string]interface{}
}

func checkToken(t, k string) error {
	token, err := parseToken(t)
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("parse token is nil")
	}

	if err = verifyToken(token, k); err != nil {
		return err
	}

	if exp := token.Payload["exp"]; exp != nil {
		if expInt, err := strconv.ParseInt(fmt.Sprint(exp), 10, 64); err != nil || expInt < time.Now().Unix() {
			return errors.New("token is expired")
		}
	}
	if nbf := token.Payload["nbf"]; nbf != nil {
		if nbfInt, err := strconv.ParseInt(fmt.Sprint(nbf), 10, 64); err != nil || nbfInt > time.Now().Add(1*time.Minute).Unix() {
			return errors.New("token not valid yet")
		}
	}

	return nil
}

func parseToken(t string) (*jwt, error) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	jwtToken := jwt{
		Plaintext: []byte(t[0 : len(parts[0])+len(parts[1])+1]),
		Signature: signature,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewBuffer(payload))
	d.UseNumber()
	err = d.Decode(&jwtToken.Payload)
	if err != nil {
		return nil, err
	}
	return &jwtToken, nil
}

func verifyToken(token *jwt, key string) error {
	supportedHeaderNames := map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}}
	for _, h := range token.Header.Crit {
		if _, ok := supportedHeaderNames[h]; !ok {
			return fmt.Errorf("unsupported header: %s", h)
		}
	}

	if token.Header.Alg != "RS256" {
		return fmt.Errorf("invalid sign method: expect rs256, get %v", token.Header.Alg)
	}

	hash := crypto.SHA256

	h := hash.New()
	_, err := h.Write(token.Plaintext)
	if err != nil {
		return err
	}

	digest := h.Sum([]byte{})

	var pk *rsa.PublicKey
	if pk, err = jwtv4.ParseRSAPublicKeyFromPEM([]byte(key)); err != nil {
		return err
	}

	if err := rsa.VerifyPKCS1v15(pk, hash, digest, token.Signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS): %w", err)
	}
	return nil
}
