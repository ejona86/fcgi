# Go FastCGI client

[![Go Reference](https://pkg.go.dev/badge/github.com/ejona86/fcgi.svg)](https://pkg.go.dev/github.com/ejona86/fcgi)

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
