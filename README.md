# oauth2go

[![build](https://github.com/oxisto/oauth2go/actions/workflows/build.yml/badge.svg)](https://github.com/oxisto/oauth2go/actions/workflows/build.yml)
[![](https://godoc.org/github.com/oxisto/oauth2go?status.svg)](https://pkg.go.dev/github.com/oxisto/oauth2go)
[![Go Report Card](https://goreportcard.com/badge/github.com/oxisto/oauth2go)](https://goreportcard.com/report/github.com/oxisto/oauth2go)
[![codecov](https://codecov.io/gh/oxisto/oauth2go/branch/main/graph/badge.svg)](https://codecov.io/gh/oxisto/oauth2go)


## What is this?

`oauth2go` aims to be a basic [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) authorization server that implements at least some of the most basic OAuth 2.0 flows. Since the canonical import name for this package is `oauth2`, it also provides type aliases for exported structs and interfaces of the [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) package, so that both OAuth 2.0 client and server structs can be accessed using an `oauth2` package. Additional structs for specialized client flows or endpoints still need to be retrieved from the corresponding sub-package, such as [`golang.org/x/oauth2/clientcredentials`](https://pkg.go.dev/golang.org/x/oauth2/clientcredentials).

In it's bare form, this package only contains an *authorization server*, which does not have any "users" or any possibility to "log in", as this is the duty of an *authentication server*. However, for convenience, the `login` package includes a very basic authentication server which implements a POST form based `/login` endpoint and a simple login form located in [`login/login.html`](login/login.html).

## Why?

This project mainly started out of the need to have a very small, embedded OAuth 2.0 authorization server, written in Go. The main use case was a "demo" or all-in-one-mode of a large micro-service application, as well as integration testing. In production deployments, this application uses a dedicated authentication server, but I wanted something for my "demo" mode. While there are some implementations out there, it was not easy to fulfill my requirements.

*I wanted something small, lean and easily embedded in my Go code, not a full-blown authentication services with thousands of adapters and backends (written in Java).*

*I wanted something that intentionally does not support legacy flows but focuses on the newer RFCs and possibly move into the direction of [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04).*

*I wanted something with zero (or almost) zero dependencies. Therefore I strictly try to only include the following dependencies: golang.org/x/oauth2, golang.org/x/crypto (which hopefully might be part of the standard library one day) and github.com/golang-jwt/jwt (which itself also has a zero dependency policy)*

## How to use?

A very simple OAuth 2.0 authorization server with an integrated authentication ("login") server can be created like this.

```golang
import (
    oauth2 "github.com/oxisto/oauth2go"
    "github.com/oxisto/oauth2go/login"
)

func main() {
    var srv *oauth2.AuthorizationServer

    srv = oauth2.NewServer(":8080",
        login.WithLoginPage(login.WithUser("admin", "admin")),
    )

    srv.ListenAndServe()
}
```

If you want to use this project as a small standalone authentication server, you can use the Docker image to spawn one. The created user and client credentials will be printed on the console.

```
docker run -p 8080:8080 ghcr.io/oxisto/oauth2go
```

A login form is available on http://localhost:8008/login.


## (To be) Implemented Standards

* [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749). The basics
* [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750). We are exclusively using JWTs as bearer tokens
* [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517). JSON Web Key
