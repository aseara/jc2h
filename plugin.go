// Package plugin a jwt auth plugin.
package plugin

import (
	"context"
	"fmt"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
	CheckCookie       bool   `json:"checkCookie,omitempty"`
	CookieName        string `json:"cookieName,omitempty"`
	CheckHeader       bool   `json:"checkHeader,omitempty"`
	HeaderName        string `json:"headerName,omitempty"`
	HeaderValuePrefix string `json:"headerValuePrefix,omitempty"`
	SsoLoginUrl       string `json:"ssoLoginUrl,omitempty"`
	InjectHeader      string `json:"injectHeader,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Jwt a Jwt plugin.
type Jwt struct {
	next   http.Handler
	config *Config
	name   string
}

// New created a new Jwt plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.CheckCookie && len(config.CookieName) == 0 {
		return nil, fmt.Errorf("cookieName cannot be empty when checkCookie is true")
	}

	if config.CheckHeader && len(config.HeaderName) == 0 {
		return nil, fmt.Errorf("headerName cannot be empty when checkHeader is true")
	}

	if (config.CheckHeader || config.CheckCookie) && len(config.SsoLoginUrl) == 0 {
		return nil, fmt.Errorf("ssoLoginURL cannot be empty when checkCookie or checkHeader is true")
	}

	return &Jwt{
		config: config,
		next:   next,
		name:   name,
	}, nil
}

func (a *Jwt) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// for key, value := range a.headers {
	//	tmpl, err := a.template.Parse(value)
	//	if err != nil {
	//		http.Error(rw, err.Error(), http.StatusInternalServerError)
	//		return
	//	}
	//
	//	writer := &bytes.Buffer{}
	//
	//	err = tmpl.Execute(writer, req)
	//	if err != nil {
	//		http.Error(rw, err.Error(), http.StatusInternalServerError)
	//		return
	//	}
	//
	//	req.Header.Set(key, writer.String())
	//}

	a.next.ServeHTTP(rw, req)
}
