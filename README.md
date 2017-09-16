# Go FastCGI client

[![Build Status](https://travis-ci.org/ejona86/fcgi.svg?branch=master)](https://travis-ci.org/ejona86/fcgi)
[![GoDoc](https://godoc.org/github.com/ejona86/fcgi?status.svg)](http://godoc.org/github.com/ejona86/fcgi)

A FastCGI client for web servers to communicate with FastCGI application
servers, like those implemented in Go with net/http/fcgi, Python, and PHP.
Based on Go's net/http/cgi and net/http/fcgi.

It is designed to be a drop-in replacement for net/http/cgi.

## Usage

```go
http.Handle("/trac/", &fcgi.Handler{
	Dialer: &fcgi.NetDialer{
		Network: "unix",
		Address: "/run/trac.socket",
	},
	Root: "/trac",
})
```
