// Package router contains the main routine of the PEP service. For each client
// request, it performs basic authentication, authorization, transformation of
// SFC into SFP and forwarding to other service functions and services.
package router

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/httplogger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/service_function"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logger.Logger

	// Service function to be called for every incoming HTTP request
	sf service_function.ServiceFunction
}

func New(logger *logger.Logger) (*Router, error) {
	var err error

	// Create a new instance of the Router
	router := new(Router)
	router.sysLogger = logger

	router.sf, err = httplogger.New()
	if err != nil {
		return nil, err
	}

	// Create a tls.Config struct to accept incoming connections
	router.tlsConfig = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: false,
		Certificates:           []tls.Certificate{config.Config.X509KeyPairShownBySFAsServer},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              config.Config.CAcertPoolPepAcceptsFromExt,
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         config.Config.SF.ListenAddr,
		TLSConfig:    router.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(router.sysLogger.GetWriter(), "", 0),
	}

	return router, nil
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Log the http request
	router.sysLogger.LogHTTPRequest(req)

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

	//fmt.Println(req.Header.Get("sfp"))

	// Read the first value of "Sfp" field (required for service HTTPZT infrastructure) of the http header
	sfp_as_string := req.Header.Get("sfp")
	req.Header.Del("sfp")

	if len(sfp_as_string) == 0 {
		// TODO: return an error?
		return
	}

	sfp_slices := strings.Split(sfp_as_string, ",")
	next_hop := sfp_slices[0]
	sfp_slices = sfp_slices[1:]
	if len(sfp_slices) != 0 {
		sfp_as_string = strings.Join(sfp_slices[:], ",")
		req.Header.Set("sfp", sfp_as_string)
	}

	service_url, _ := url.Parse(next_hop)
	proxy := httputil.NewSingleHostReverseProxy(service_url)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		IdleConnTimeout:     10 * time.Second,
		MaxIdleConnsPerHost: 10000,
		TLSClientConfig: &tls.Config{
			Certificates:           []tls.Certificate{config.Config.X509KeyPairShownBySFAsClient},
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: false,
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              config.Config.CAcertPoolPepAcceptsFromInt,
		},
	}
	proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}
