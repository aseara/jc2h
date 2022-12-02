// Package jc2h plugin a jwt auth plugin.
package jc2h

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
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
	key    any
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

	var k any
	if config.CheckHeader || config.CheckCookie {
		if len(config.SignKey) == 0 {
			return nil, fmt.Errorf("signKey cannot be empty when checkCookie or checkHeader is true")
		}

		var err error
		k, err = parseKey(config.SignKey)
		if err != nil {
			return nil, fmt.Errorf("signKey is not valid: %w", err)
		}
	}

	return &JwtPlugin{
		name:   name,
		config: config,
		key:    k,
		next:   next,
	}, nil
}

func parseKey(signKey string) (any, error) {
	key := []byte(signKey)
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	}

	// Parse the key
	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	return parsedKey, nil
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

	c, err := j.checkToken(t)
	if err != nil || !c {
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

func (j *JwtPlugin) checkToken(t string) (bool, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (any, error) {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(j.config.SignKey))
	})

	if errors.Is(err, jwt.ErrTokenMalformed) {
		log.Println("jwt.ServeHTTP jwt token is malformed")
	} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
		fmt.Println("jwt.ServeHTTP token is either expired or not active yet")
	}

	if token.Valid && token.Method != jwt.SigningMethodRS256 {
		return false, fmt.Errorf("invalid sign method: expect rs256, get %v", token.Method)
	}

	return token.Valid, err
}

func redirectToLogin(c *Config, rw http.ResponseWriter, req *http.Request) {
	var b strings.Builder
	b.WriteString(c.SsoLoginURL)
	b.WriteString("?ReturnUrl=")
	b.WriteString(req.URL.Scheme)
	b.WriteString("://")
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
