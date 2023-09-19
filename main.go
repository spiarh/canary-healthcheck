package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func newHTTPServer(port string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Println(err)
		}
	})

	return &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 60 * time.Second,
	}
}

// serverErrorLogWriter is used to filter error logs from the probes
// https://github.com/golang/go/issues/26918
type serverErrorLogWriter struct{}

func (*serverErrorLogWriter) Write(p []byte) (int, error) {
	m := string(p)
	// http: TLS handshake error from 127.0.0.1:55798: remote error: tls: bad certificate
	if !(strings.HasPrefix(m, "http: TLS handshake error") && strings.HasSuffix(m, "remote error: tls: bad certificate\n")) {
		log.Print(m)
	}
	return len(p), nil
}

var _ io.Writer = &serverErrorLogWriter{}

func newServerErrorLog() *log.Logger {
	return log.New(&serverErrorLogWriter{}, "", 0)
}

func newHTTPSServer(port string, pair tls.Certificate) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Println(err)
		}
	})

	return &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		// https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{pair},
			CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519},
			MinVersion:       tls.VersionTLS13,
		},
		// disable HTTP/2 - https://pkg.go.dev/net/http#pkg-overview
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadHeaderTimeout: 60 * time.Second,
		ErrorLog:          newServerErrorLog(),
	}
}

func main() {
	var (
		HTTPPort, HTTPSPort string
		TLSKeyPairPath      string
	)

	flag.StringVar(&HTTPPort, "http-port", "8080", "Port to run the HTTP server")
	flag.StringVar(&HTTPSPort, "https-port", "8443", "Port to run the HTTPS server")
	flag.StringVar(&TLSKeyPairPath, "tls-key-pair-path", "/certs", "Path with the tls.crt and tls.key files")
	flag.Parse()

	stopCh := handleSignals()

	// HTTP Server
	HTTPServer := newHTTPServer(HTTPPort)

	// HTTPS Server
	TLSKeyPairPath = filepath.Clean(TLSKeyPairPath)
	pair, err := tls.LoadX509KeyPair(filepath.Join(TLSKeyPairPath, "tls.crt"), filepath.Join(TLSKeyPairPath, "tls.key"))
	if err != nil {
		log.Fatalf("failed to load x509 key pair: %v", err)
	}
	HTTPSServer := newHTTPSServer(HTTPSPort, pair)

	defer func() {
		log.Println("shutting down HTTP server")
		if err := HTTPServer.Shutdown(context.TODO()); err != nil {
			log.Println(err)
		}

		log.Println("shutting down HTTPS server")
		if err := HTTPSServer.Shutdown(context.TODO()); err != nil {
			log.Println(err)
		}

		log.Println("canary-healthcheck stopped")
	}()

	log.Print("starting HTTP Server")
	go func() {
		if err := HTTPServer.ListenAndServe(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				log.Println(err)
				return
			}
			log.Fatal(err)
		}
	}()

	log.Print("starting HTTPS Server")
	go func() {
		if err := HTTPSServer.ListenAndServeTLS("", ""); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				log.Println(err)
				return
			}
			log.Fatal(err)
		}
	}()
	log.Print("canary-healthcheck started")

	<-stopCh
}

// handleSignals shutdowns gracefully on SIGINT and SIGTEM signals.
func handleSignals() chan struct{} {
	sigCh := make(chan os.Signal, 1)
	stopCh := make(chan struct{})
	go func() {
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		stopCh <- struct{}{}
	}()
	return stopCh
}
