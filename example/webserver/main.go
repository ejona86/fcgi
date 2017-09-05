package main

import (
	"github.com/ejona86/fcgi"
	"log"
	"net/http"
	"net/http/cgi"
)

func main() {
	// Assumes php-fpm is running in ../app directory
	http.Handle("/php-fcgi", &fcgi.Handler{
		Dialer: &fcgi.NetDialer{
			Network: "unix",
			Address: "/run/php-fpm/php-fpm.sock",
		},
		Env: []string{
			"SCRIPT_FILENAME=index.php",
		},
	})
	http.Handle("/php-cgi", &cgi.Handler{
		Path: "/usr/bin/php-cgi",
		Dir:  "../app/",
		Env: []string{
			"SCRIPT_FILENAME=index.php",
			"REDIRECT_STATUS=trash",
		},
	})

	// Assumes ../app/app is running in ../app directory
	http.Handle("/go-fcgi", &fcgi.Handler{
		Dialer: &fcgi.NetDialer{
			Network: "unix",
			Address: "../app.socket",
		},
	})
	http.Handle("/go-cgi", &cgi.Handler{
		Path: "../app/app",
		Dir:  "../app/",
		Args: []string{"cgi"},
	})

	// Assumes ../app/index.py is running in ../app directory
	http.Handle("/py-fcgi", &fcgi.Handler{
		Dialer: &fcgi.NetDialer{
			Network: "unix",
			Address: "../app-py.socket",
		},
	})
	http.Handle("/py-cgi", &cgi.Handler{
		Path: "../app/index.py",
		Dir:  "../app/",
		Args: []string{"cgi"},
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
