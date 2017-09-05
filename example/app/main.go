package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/fcgi"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello from Go\n")
	}))
	if len(os.Args) > 1 && os.Args[1] == "cgi" {
		cgi.Serve(nil)
	} else {
		l, err := net.Listen("unix", "../app.socket")
		if err != nil {
			log.Fatal("Failed to listen: ", err)
		}
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-ch
			l.Close()
		}()
		log.Fatal(fcgi.Serve(l, nil))
	}
}
