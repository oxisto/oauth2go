# oauth2go

[![build](https://github.com/oxisto/oauth2go/actions/workflows/build.yml/badge.svg)](https://github.com/oxisto/oauth2go/actions/workflows/build.yml)
[![](https://godoc.org/github.com/oxisto/oauth2go?status.svg)](https://pkg.go.dev/github.com/oxisto/oauth2go)
[![Go Report Card](https://goreportcard.com/badge/github.com/oxisto/oauth2go)](https://goreportcard.com/report/github.com/oxisto/oauth2go)
[![codecov](https://codecov.io/gh/oxisto/oauth2go/branch/main/graph/badge.svg)](https://codecov.io/gh/oxisto/oauth2go)


## What is this?

`oauth2go` aims to be a basic [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) server that implements at least some of the most basic OAuth 2.0 flows.

## Why?

This project mainly started out of the need to have a very small, embedded OAuth 2.0 server. The main use case was a "demo" or all-in-one-mode of a large micro-service application. In production deployments, this application uses a dedicated authentication server, but I wanted something for my "demo" mode. While there are some implementations out there, it was not easy to fulfill my requirements.

*I wanted something small, lean and easily embedded in my Go code, not a full-blown authentication services with thousands of adapters and backends (written in Java).*

*I wanted something that intentionally does not support legacy flows but focuses on the newer RFCs and possibly move into the direction of [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04).*

*I wanted something with zero (or almost) zero dependencies. Therefore I strictly try to only include the following dependencies: golang.org/x/oauth2 (which hopefully might be part of the standard library one day) and github.com/golang-jwt/jwt (which itself also has a zero dependency policy)*

## How to use?

Well, I have to program it first.

## (To be) Implemented Standards

* [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749). The basics
* [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750). We are exclusively using JWTs as bearer tokens
* [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517). JSON Web Key
* 