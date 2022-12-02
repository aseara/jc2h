This repository includes a traefik plugin, `jwt`, It can check jwt from cookie or header. And It has optional configuration to set jwt to another header for backend.

For now only supports RS256 algorithm.

[![Build Status](https://github.com/aseara/jc2h/workflows/Main/badge.svg?branch=master)](https://github.com/aseara/jc2h/actions)

## Configuration

The plugin needs to be configured in the Traefik static configuration before it can be used.

### Installation with Helm

```values.yaml
# snippet from helm values.yaml
experimental:
  plugins:
    enabled: true

additionalArguments:
- --experimental.plugins.traefik-jwt-middleware.moduleName=github.com/aseara/jc2h
- --experimental.plugins.traefik-jwt-middleware.version=v0.1.2
```

### Installation via command line
```yaml
# Static configuratio
experimental:
  plugins:
    traefik-jwt-middleware:
      moduleName: github.com/aseara/jc2h
      version: v0.1.2
```

#
## Configuration
The plugin currently supports the following configuration settings: (all fields are optional)

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

#
## Example configuration
This example uses Kubernetes Custom Resource Descriptors (CRD) :
```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: traefik-jwt-plugin
spec:
  plugin:
    traefik-jwt-plugin:
      checkCookie: true
      cookieName: jwt-token
      ssoLoginUrl: https://sso.xxxx.cn
      injectHeader: X-JWT-TOKEN
      signKey: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
          vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
          aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
          tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
          e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
          V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
          MwIDAQAB
          -----END PUBLIC KEY-----
```

Activate plugin in your config
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-server
  labels:
    app: test-server
  annotations:
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/router.middlewares: traefik-jwt-plugin@kubernetescrd
```