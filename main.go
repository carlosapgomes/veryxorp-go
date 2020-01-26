package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/acme/autocert"
)

func makeServerFromMux(mux *http.ServeMux) *http.Server {
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
}

func makeHTTPServer(handler http.Handler) *http.Server {
	mux := &http.ServeMux{}
	mux.Handle("/", handler)
	return makeServerFromMux(mux)

}

func makeHTTPToHTTPSRedirectServer() *http.Server {
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleRedirect)
	return makeServerFromMux(mux)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	file, err := os.OpenFile("/var/log/veryxorp/app.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	log.SetOutput(file)

	certDir, ok := os.LookupEnv("CERTS_DIR")
	if !ok {
		certDir = "/certs"
	}

	allowedDomain, ok := os.LookupEnv("ALLOWED_DOMAIN")
	if !ok {
		log.Fatal("A domain name is required (set $ALLOWED_DOMAIN")
	}

	internalHost, ok := os.LookupEnv("INTERNAL_HOST")
	if !ok {
		log.Fatal("An internal host name/ip is required (set $INTERNAL_HOST")
	}

	internalPort, ok := os.LookupEnv("INTERNAL_PORT")
	if !ok {
		log.Fatal("An internal port number is required (set $INTERNAL_PORT")
	}

	var m *autocert.Manager

	var httpsSrv *http.Server
	hostPolicy := func(ctx context.Context, host string) error {
		allowedHost := allowedDomain
		if host == allowedHost {
			return nil
		}
		return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
	}

	m = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(certDir),
	}

	u, _ := url.Parse("http://" + internalHost + ":" + internalPort)
	mux := http.NewServeMux()
	mux.Handle("/", httputil.NewSingleHostReverseProxy(u))
	httpsSrv = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
	httpsSrv.Addr = ":443"
	httpsSrv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

	go func() {
		fmt.Printf("Starting HTTPS server on %s\n", httpsSrv.Addr)
		err := httpsSrv.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
		}
	}()

	var httpSrv *http.Server

	httpSrv = makeHTTPToHTTPSRedirectServer()

	// allow autocert handle Let's Encrypt callbacks over http
	if m != nil {
		httpSrv.Handler = m.HTTPHandler(httpSrv.Handler)
	}

	httpSrv.Addr = ":80"
	fmt.Printf("Starting HTTP server on %s\n", httpSrv.Addr)
	err = httpSrv.ListenAndServe()
	if err != nil {
		log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
	}
}
