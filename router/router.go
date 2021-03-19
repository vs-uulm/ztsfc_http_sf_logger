package router

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	env "local.com/leobrada/ztsfc_http_sf_logger/env"
	logwriter "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
	service_function "local.com/leobrada/ztsfc_http_sf_logger/service_function"
)

type Router struct {
	// SF tls config (when acts as a server)
	tls_config *tls.Config

	// HTTP server\
	frontend *http.Server

	// SF certificate and CA (when acts as a server)
	router_cert_when_acts_as_a_server    tls.Certificate
	router_ca_pool_when_acts_as_a_server *x509.CertPool

	// SF certificate and CA (when acts as a client)
	router_cert_when_acts_as_a_client    tls.Certificate
	router_ca_pool_when_acts_as_a_client *x509.CertPool

	// Service function to be called for every incoming HTTP request
	sf service_function.ServiceFunction

	// Logger structs
	lw *logwriter.LogWriter
}

func NewRouter(_sf service_function.ServiceFunction, _lw *logwriter.LogWriter) (*Router, error) {
	router := new(Router)
	router.lw = _lw
	router.sf = _sf

	// router.lw.Logger.Debugf("An instance of service function %s has been created", router.sf.GetSFName())

	// Load all SF certificates to operate both in server and client modes
	router.initAllCertificates(&env.Config)

	// Initialize TLS configuration to handle only secure connections
	router.tls_config = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{router.router_cert_when_acts_as_a_server},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              router.router_ca_pool_when_acts_as_a_server,
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	// Create an HTTP server to handle all incoming requests
	router.frontend = &http.Server{
		Addr:         env.Config.Sf.Listen_addr,
		TLSConfig:    router.tls_config,
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
		Handler:      mux,
		ErrorLog:     log.New(router.lw, "", 0),
	}
	return router, nil
}


// The ServeHTTP() function operates every incoming http request
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// Log the http request
	router.lw.LogHTTPRequest(req)

	// Call the service function main algorithm
	// If the algorithm return value is true:
	//     extract an <IP address>/<DNS name> of the next service function or service in the chain
	//     forward the packet
	// If the algorithm return value is false:
	//     drop the packet

	forward := router.sf.ApplyFunction(w, req)
	if !forward {
		return
	}

	// ToDo: add extracting of the next hop address from the list of IPs

	// Read the first value of "Sfp" field (required for service HTTPZT infrastructure) of the http header
	dst := req.Header.Get("Sfp")
	req.Header.Del("Sfp")
	service_url, _ := url.Parse(dst)
	proxy := httputil.NewSingleHostReverseProxy(service_url)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{router.router_cert_when_acts_as_a_client},
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          router.router_ca_pool_when_acts_as_a_client,
		},
	}
	proxy.ServeHTTP(w, req)
}

// The ListenAndServeTLS() function runs the HTTPS server
func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}

// The makeCAPool() function creates a CA pool and loads a certificate from a file with the provided path
func makeCAPool(path string) (ca_cert_pool *x509.CertPool, ok bool) {

	// Create a new CA pool
	ca_cert_pool = x509.NewCertPool()

	// Reading of the certificate file content
	ca_cert, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("[Router.makeCAPool]: ReadFile: ", err)
		return ca_cert_pool, false
	}

	// Parsing a series of PEM encoded certificate(s).
	ok = ca_cert_pool.AppendCertsFromPEM(ca_cert)
	if !ok {
		fmt.Printf("[Router.makeCAPool]: AppendCertsFromPEM: ", err)
		return ca_cert_pool, false
	}

	return ca_cert_pool, true
}

// The initAllCertificates() function loads all certificates from certificate files.
func (router *Router) initAllCertificates(conf *env.Config_t) {
	var err error
	var ok bool

	//
	// 1. Server section
	//
	// 1.1: Load SF Cert that is shown when SF operates as a server
	router.router_cert_when_acts_as_a_server, err = tls.LoadX509KeyPair(env.Config.Sf.Server.Cert_shown_by_sf, env.Config.Sf.Server.Privkey_for_cert_shown_by_sf)
	if err != nil {
		router.lw.Logger.Fatalf("Critical Error when loading external X509KeyPair from %s and %s: %v", env.Config.Sf.Server.Cert_shown_by_sf, env.Config.Sf.Server.Privkey_for_cert_shown_by_sf, err)
	} else {
		router.lw.Logger.Debugf("External X509KeyPair from %s and %s is successfully loaded", env.Config.Sf.Server.Cert_shown_by_sf, env.Config.Sf.Server.Privkey_for_cert_shown_by_sf)
	}

	// 1.2: Load the CA's root certificate that was used to sign all incoming requests certificates
	router.router_ca_pool_when_acts_as_a_server, ok = makeCAPool(conf.Sf.Server.Certs_sf_accepts)
	if !ok {
		router.lw.Logger.Fatalf("Critical Error when loading CA certificate to sign incoming requests from %s", conf.Sf.Server.Certs_sf_accepts)
	} else {
		router.lw.Logger.Debugf("CA certificate to sign incoming requests from %s is successfully loaded", conf.Sf.Server.Certs_sf_accepts)
	}

	//
	// 2. Client section
	//
	// 2.1: Load SF Cert that is shown when SF operates as a client
	router.router_cert_when_acts_as_a_client, err = tls.LoadX509KeyPair(env.Config.Sf.Client.Cert_shown_by_sf, env.Config.Sf.Client.Privkey_for_cert_shown_by_sf)
	if err != nil {
		router.lw.Logger.Fatalf("Critical Error when loading internal X509KeyPair from %s and %s: %v", env.Config.Sf.Client.Cert_shown_by_sf, env.Config.Sf.Client.Privkey_for_cert_shown_by_sf, err)
	} else {
		router.lw.Logger.Debugf("External X509KeyPair from %s and %s is successfully loaded", env.Config.Sf.Client.Cert_shown_by_sf, env.Config.Sf.Client.Privkey_for_cert_shown_by_sf)
	}

	// 2.2: Load the CA's root certificate that was used to sign certificates of the SF connection destination
	router.router_ca_pool_when_acts_as_a_client, ok = makeCAPool(conf.Sf.Client.Certs_sf_accepts)
	if !ok {
		router.lw.Logger.Fatalf("Critical Error when loading CA certificate to sign outgoing connections from %s", conf.Sf.Client.Certs_sf_accepts)
	} else {
		router.lw.Logger.Debugf("CA certificate to sign outgoing connections from %s is successfully loaded", conf.Sf.Client.Certs_sf_accepts)
	}
}
