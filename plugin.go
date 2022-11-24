// Package plugin a jwt auth plugin.
package plugin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	CheckCookie       bool   `json:"checkCookie,omitempty"`
	CookieName        string `json:"cookieName,omitempty"`
	CheckHeader       bool   `json:"checkHeader,omitempty"`
	HeaderName        string `json:"headerName,omitempty"`
	HeaderValuePrefix string `json:"headerValuePrefix,omitempty"`
	PublicKey         string `json:"publicKey,omitempty"`
	SsoLoginUrl       string `json:"ssoLoginUrl,omitempty"`
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

	if (config.CheckHeader || config.CheckCookie) && len(config.SsoLoginUrl) == 0 {
		return nil, fmt.Errorf("ssoLoginURL cannot be empty when checkCookie or checkHeader is true")
	}

	if (config.CheckHeader || config.CheckCookie) && len(config.PublicKey) == 0 {
		return nil, fmt.Errorf("publicKey cannot be empty when checkCookie or checkHeader is true")
	}

	k, err := parseKey(config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("publicKey is not valid: %v", err)
	}

	return &JwtPlugin{
		name:   name,
		config: config,
		key:    k,
		next:   next,
	}, nil
}

func (j *JwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Println("jwt.ServeHTTP jwt.name:", j.name)
	log.Println("jwt.ServeHTTP req.URL:", req.URL)
	log.Println("jwt.ServeHTTP.req.Host:", req.Host)
	log.Println("jwt.ServeHTTP.req.RequestURI:", req.RequestURI)
	b, _ := json.Marshal(j.config)
	log.Println("jwt.ServeHTTP jwt.config:", string(b))

	if !j.config.CheckCookie && !j.config.CheckHeader {
		log.Println("jwt.ServeHTTP no need to check cookie or header, pass through")
		j.next.ServeHTTP(rw, req)
	}

	t := getToken(req, j.config)
	if len(t) == 0 {
		log.Println("jwt.ServeHTTP jwt token is nil", http.StatusInternalServerError)
		redirectToLogin(j.config, rw, req)
		return
	}

	c, err := checkToken(t, j.key)
	if err != nil || !c {
		log.Println("jwt.ServeHTTP token valid false", http.StatusInternalServerError, err)
		redirectToLogin(j.config, rw, req)
		return
	}

	if len(j.config.InjectHeader) != 0 {
		req.Header.Set(j.config.InjectHeader, t)
	}

	log.Println("jwt.ServeHTTP success")
	j.next.ServeHTTP(rw, req)
}

func parseKey(p string) (any, error) {
	if block, rest := pem.Decode([]byte(p)); block != nil {
		if len(rest) > 0 {
			return nil, fmt.Errorf("extra data after a PEM certificate block in publicKey")
		}
		if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
			return x509.ParsePKIXPublicKey(block.Bytes)
		}
	}
	return nil, fmt.Errorf("failed to extract a Key from the publicKey")
}

func getToken(req *http.Request, c *Config) (t string) {
	if c.CheckHeader {
		t = req.Header.Get(c.HeaderName)
		if len(t) != 0 && len(c.HeaderValuePrefix) != 0 {
			t = strings.TrimPrefix(t, c.HeaderValuePrefix)
		}
	}
	if len(t) == 0 && c.CheckCookie {
		for _, cookie := range req.Cookies() {
			if cookie.Name == c.CookieName {
				t = cookie.Value
				break
			}
		}
	}

	if len(t) != 0 {
		t = strings.TrimSpace(t)
	}
	return
}

type JwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}

var supportedHeaderNames = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}}

type jwt struct {
	Plaintext []byte
	Signature []byte
	Header    JwtHeader
	Payload   map[string]interface{}
}

func checkToken(t string, k any) (c bool, err error) {
	jwt, err := extractToken(t)
	if err != nil {
		return
	}

	if err = verifySignature(jwt, k); err != nil {
		return
	}

	expInt, err := strconv.ParseInt(fmt.Sprint(jwt.Payload["exp"]), 10, 64)
	if err != nil || expInt < time.Now().Unix() {
		return false, fmt.Errorf("token is expired")
	}

	nbfInt, err := strconv.ParseInt(fmt.Sprint(jwt.Payload["nbf"]), 10, 64)
	if err != nil || nbfInt > time.Now().Add(1*time.Minute).Unix() {
		return false, fmt.Errorf("token not valid yet")
	}

	return true, nil
}

func extractToken(t string) (*jwt, error) {
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		log.Println("jwt.ServeHTTP invalid token format, expected 3 parts")
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
		Plaintext: []byte(t[:len(parts[0])+len(parts[1])+1]),
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

func verifySignature(jwt *jwt, key any) error {
	for _, h := range jwt.Header.Crit {
		if _, ok := supportedHeaderNames[h]; !ok {
			return fmt.Errorf("unsupported header: %s", h)
		}
	}
	// Look up the algorithm
	a, ok := tokenAlgorithms[jwt.Header.Alg]
	if !ok {
		return fmt.Errorf("unknown JWS algorithm: %s", jwt.Header.Alg)
	}
	return a.verify(key, a.hash, jwt.Plaintext, jwt.Signature)
}

func redirectToLogin(c *Config, rw http.ResponseWriter, req *http.Request) {
	var b strings.Builder
	b.WriteString(c.SsoLoginUrl)
	b.WriteString("?ReturnUrl=https://")
	b.WriteString(req.Host)
	b.WriteString(req.RequestURI)

	location := b.String()
	log.Println("jwt.ServeHTTP redirect to:", location)

	rw.Header().Set("Location", location)
	status := http.StatusTemporaryRedirect
	rw.WriteHeader(status)
	_, err := rw.Write([]byte(http.StatusText(status)))

	if err != nil {
		log.Println("jwt.ServeHTTP redirect err:", http.StatusInternalServerError, err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

type tokenVerifyFunction func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error
type tokenVerifyAsymmetricFunction func(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error

// jwtAlgorithm describes a JWS 'alg' value
type tokenAlgorithm struct {
	hash   crypto.Hash
	verify tokenVerifyFunction
}

// tokenAlgorithms is the known JWT algorithms
var tokenAlgorithms = map[string]tokenAlgorithm{
	"RS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPKCS)},
	"RS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPKCS)},
	"RS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPKCS)},
	"PS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPSS)},
	"PS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPSS)},
	"PS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPSS)},
	"ES256": {crypto.SHA256, verifyAsymmetric(verifyECDSA)},
	"ES384": {crypto.SHA384, verifyAsymmetric(verifyECDSA)},
	"ES512": {crypto.SHA512, verifyAsymmetric(verifyECDSA)},
	"HS256": {crypto.SHA256, verifyHMAC},
	"HS384": {crypto.SHA384, verifyHMAC},
	"HS512": {crypto.SHA512, verifyHMAC},
}

// errSignatureNotVerified is returned when a signature cannot be verified.
func verifyHMAC(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
	macKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("incorrect symmetric key type")
	}
	mac := hmac.New(hash.New, macKey)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	sum := mac.Sum([]byte{})
	if !hmac.Equal(signature, sum) {
		return fmt.Errorf("token verification failed (HMAC)")
	}
	return nil
}

func verifyAsymmetric(verify tokenVerifyAsymmetricFunction) tokenVerifyFunction {
	return func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa := key.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(publicKeyRsa, hash, digest, signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS)")
	}
	return nil
}

func verifyRSAPSS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	if err := rsa.VerifyPSS(publicKeyRsa, hash, digest, signature, nil); err != nil {
		return fmt.Errorf("token verification failed (RSAPSS)")
	}
	return nil
}

func verifyECDSA(key interface{}, _ crypto.Hash, digest []byte, signature []byte) error {
	publicKeyEcdsa, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	r, s := &big.Int{}, &big.Int{}
	n := len(signature) / 2
	r.SetBytes(signature[:n])
	s.SetBytes(signature[n:])
	if ecdsa.Verify(publicKeyEcdsa, digest, r, s) {
		return nil
	}
	return fmt.Errorf("token verification failed (ECDSA)")
}
