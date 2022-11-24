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

| Setting   | Allowed values | Description |
| :--       | :--            | :--         |
| name      | string   | Name of the request header |
| matchtype | one, all | Match on all values or one of the values specified. The value 'all' is only allowed in combination with the 'contains' setting.|
| values    | []string | A list of allowed values which are matched against the request header value|
| contains  | boolean  | If set to true (default false), the request is allowed if the rtequest header value contains the value specified in the configuration |
| required  | boolean  | If set to false (default true), the request is allowed if the header is absent or the value is empty|
| urldecode | boolean  | If set to true (default false), the value of the request header will be URL decoded before further processing with the plugin. This is useful when using this plugin with the [PassTLSClientCert](https://doc.traefik.io/traefik/middlewares/passtlsclientcert/) middleware that Traefik offers.
| debug     | boolean  | If set to true (default false), the request headers, values and validation will be printed to the console|