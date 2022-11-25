This repository includes a traefik plugin, `jwt`, It can check jwt from cookie or header. And It has optional configuration to set jwt to another header for backend.

[![Build Status](https://github.com/aseara/traefik-jwt-plugin/workflows/Main/badge.svg?branch=master)](https://github.com/aseara/traefik-jwt-plugin/actions)

## Configuration

Start with command
```yaml
# Static configuratio
experimental:
  plugins:
    traefik-jwt-middleware:
      moduleName: github.com/aseara/traefik-jwt-plugin
      version: v0.1.0
```

#

Activate plugin in your config

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - my-plugin

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    my-plugin:
      plugin:
        traefik-jwt-middleware:
          queryParam: token
          secret: secret
```

#
Supported parameter

| Setting            | Allowed values | Description |
| :--                | :--            | :--         |
| checkCookie        | boolean        | If set to true, will try extract token from cookie with cookieName unless checkHeader is set to true and token is extracted from header.|
| cookieName         | string         | Used as cookie name when extracting token from cookie. Needed if checkCookie is true.|
| checkHeader        | boolean        | If set to true, will try extract token from header with headerName.|
| headerName         | string         | Used to extract token from header. When checkHeader is true and this is empty, headerName will be set to Default value is 'Authorization' and headerValuePrefix to 'Bearer'.|
| headerValuePrefix  | string         | When extract token from header, this will be the prefix of header value.|
| signKey            | string         | PEM format public key to verify the jwt token. Cannot be empty when checkCookie or checkHeader is true.|
| ssoLoginUrl        | string         | login url to redirect when token invalid. Cannot be empty when checkCookie or checkHeader is true.|
| injectHeader       | string         | If set , the jwt token will be injected into request header with injectHeader value as key.|