package router

import (
    "io/ioutil"
    "crypto/x509"
    "crypto/tls"
    "net/http"
    "net/http/httputil"
    "time"
    "fmt"
    "net/url"
    "log"

    env "local.com/leobrada/ztsfc_http_sf_logger/env"
    service_function "local.com/leobrada/ztsfc_http_sf_logger/service_function"

    "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
)

const (
    NONE = iota
    BASIC
    ADVANCED
    DEBUG
    ALL
)

type Router struct {
    // SF tls config (when acts as a server)
    tls_config *tls.Config

    // HTTP server
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
    logger *log.Logger
    logLevel int
    logChannel chan []byte
    logWriter *logwriter.LogWriter
}

func getLogFilePath() string {
    return "./access.log"
}

func NewRouter(_sf service_function.ServiceFunction,
               _log_level int) (*Router, error) {
    router := new(Router)
    router.logLevel = _log_level
    router.sf = _sf

    // Create a logging channel
    router.logChannel = make(chan []byte, 256)

    // Create a new log writer
    router.logWriter = logwriter.NewLogWriter(getLogFilePath, router.logChannel, 5)

    // Run main loop of logWriter
    go router.logWriter.Work()
    
    router.Log(DEBUG, "============================================================\n")
    router.Log(DEBUG, "A new service function has been created\n")    

    // Load all SF certificates to operate both in server and client modes
    router.initAllCertificates(&env.Config)

    // Initialize TLS configuration to handle only secure connections
    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: []tls.Certificate{router.router_cert_when_acts_as_a_server},
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: router.router_ca_pool_when_acts_as_a_server,
    }

    // Frontend Handlers
    mux := http.NewServeMux()
    mux.Handle("/", router)

    // Frontend Loggers
    router.logger = log.New(logwriter.LogWriter{}, "", log.LstdFlags)

    // Create an HTTP server to handle all incoming requests
    router.frontend = &http.Server {
        Addr: env.Config.Sf.Listen_addr,
        TLSConfig: router.tls_config,
        ReadTimeout: time.Second * 5,
        WriteTimeout: time.Second *5,
        Handler: mux,
        ErrorLog: router.logger,
    }
    return router, nil
}

// // // // Printing request details
// // // func (router *Router) printRequest(w http.ResponseWriter, req *http.Request) {
    // // // fmt.Printf("Method: %s\n", req.Method)
    // // // fmt.Printf("URL: %s\n", req.URL)
    // // // fmt.Printf("Protocol Version: %d.%d\n", req.ProtoMajor, req.ProtoMinor)
    // // // fmt.Println("===================HEADER FIELDS=======================")
    // // // for key, value := range req.Header {
        // // // fmt.Printf("%s: %v\n", key, value)
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Printf("Body: %s\n", "TBD")
    // // // fmt.Printf("Content Length: %d\n", req.ContentLength)
    // // // fmt.Printf("Transfer Encoding: %v\n", req.TransferEncoding)
    // // // fmt.Printf("Close: %v\n", req.Close)
    // // // fmt.Printf("Host: %s\n", req.Host)
    // // // fmt.Println("====================FORM======================")
    // // // if err := req.ParseForm(); err == nil {
        // // // for key, value := range req.Form {
            // // // fmt.Printf("%s: %v\n", key, value)
        // // // }
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Println("====================POST FORM======================")
    // // // for key, value := range req.PostForm {
        // // // fmt.Printf("%s: %v\n", key, value)
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Println("====================MULTIPART FORM======================")
    // // // if err := req.ParseMultipartForm(100); err == nil {
        // // // for key, value := range req.MultipartForm.Value {
            // // // fmt.Printf("%s: %v\n", key, value)
        // // // }
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Println("===================TRAILER HEADER=======================")
    // // // for key, value := range req.Trailer {
        // // // fmt.Printf("%s: %v\n", key, value)
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Printf("Remote Address: %s\n", req.RemoteAddr)
    // // // fmt.Printf("Request URI: %s\n", req.RequestURI)
    // // // fmt.Printf("TLS: %s\n", "TBD")
    // // // fmt.Printf("Cancel: %s\n", "TBD")
    // // // fmt.Printf("Reponse: %s\n", "TBD")
// // // }

// // // func (router *Router) SetUpSFC() bool {
    // // // return true
// // // }

func matchTLSConst(input uint16) string {
    switch input {
    // TLS VERSION
    case 0x0300:
        return "VersionSSL30"
    case 0x0301:
        return "VersionTLS10"
    case 0x0302:
        return "VersionTLS11"
    case 0x0303:
        return "VersionTLS12"
    case 0x0304:
        return "VersionTLS13"
    // TLS CIPHER SUITES
    case 0x0005:
        return "TLS_RSA_WITH_RC4_128_SHA"
    case 0x000a:
        return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    case 0x002f:
        return "TLS_RSA_WITH_AES_128_CBC_SHA"
    case 0x0035:
        return "TLS_RSA_WITH_AES_256_CBC_SHA"
    case 0x003c:
        return "TLS_RSA_WITH_AES_128_CBC_SHA256"
    case 0x009c:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256"
    case 0x009d:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384"
    case 0xc007:
        return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
    case 0xc009:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    case 0xc00a:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    case 0x1301:
        return "TLS_AES_128_GCM_SHA256"
    case 0x1302:
        return "TLS_AES_256_GCM_SHA384"
    case 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256"
    case 0x5600:
        return "TLS_FALLBACK_SCSV"
    default:
        return "unsupported"
    }
}


// The ServeHTTP() function operates every incoming http request
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

    // Log the http request
    router.LogHTTPRequest(DEBUG, req)

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
        TLSClientConfig: &tls.Config {
            Certificates: []tls.Certificate{router.router_cert_when_acts_as_a_client},
            InsecureSkipVerify: true,
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs: router.router_ca_pool_when_acts_as_a_client,
        },
    }
    proxy.ServeHTTP(w, req)
}


// The ListenAndServeTLS() function runs the HTTPS server
func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
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
    isErrorDetected := false

    //
    // 1. Server section
    //
    // 1.1: Load SF Cert that is shown when SF operates as a server
    router.Log(DEBUG, "Loading SF certificate to show to clients:\n")
    router.Log(DEBUG, fmt.Sprintf("    cert: %s\n", env.Config.Sf.Server.Cert_shown_by_sf))
    router.Log(DEBUG, fmt.Sprintf("    key:  %s\n", env.Config.Sf.Server.Privkey_for_cert_shown_by_sf))
        
    router.router_cert_when_acts_as_a_server, err = tls.LoadX509KeyPair(
        env.Config.Sf.Server.Cert_shown_by_sf,
        env.Config.Sf.Server.Privkey_for_cert_shown_by_sf)
    if err!=nil {
        isErrorDetected = true
        router.Log(DEBUG, "    Result: FAILED\n")
    } else {
        router.Log(DEBUG, "    Result: OK\n")
    }

    // 1.2: Load the CA's root certificate that was used to sign all incoming requests certificates
    router.Log(DEBUG, "Loading SF certificate to sign incoming requests:\n")
    router.Log(DEBUG, fmt.Sprintf("    CA cert: %s\n", conf.Sf.Server.Certs_sf_accepts))
       
    router.router_ca_pool_when_acts_as_a_server, ok = makeCAPool(conf.Sf.Server.Certs_sf_accepts)
    if !ok {
        isErrorDetected = true
        router.Log(DEBUG, "    Result: FAILED\n")
    } else {
        router.Log(DEBUG, "    Result: OK\n")
    }

    //
    // 2. Client section
    //
    // 2.1: Load SF Cert that is shown when SF operates as a client
    router.Log(DEBUG, "Loading SF client certificate to connect to other SFs or service:\n")
    router.Log(DEBUG, fmt.Sprintf("    cert: %s\n", env.Config.Sf.Client.Cert_shown_by_sf))
    router.Log(DEBUG, fmt.Sprintf("    key:  %s\n", env.Config.Sf.Client.Privkey_for_cert_shown_by_sf))
        
    router.router_cert_when_acts_as_a_client, err = tls.LoadX509KeyPair(
        env.Config.Sf.Client.Cert_shown_by_sf,
        env.Config.Sf.Client.Privkey_for_cert_shown_by_sf)
    if err!=nil {
        isErrorDetected = true
        router.Log(DEBUG, "    Result: FAILED\n")
    } else {
        router.Log(DEBUG, "    Result: OK\n")
    }

    // 2.2: Load the CA's root certificate that was used to sign certificates of the SF connection destination
    router.Log(DEBUG, "Loading SF certificate to sign certificates of other SFs or service:\n")
    router.Log(DEBUG, fmt.Sprintf("    CA cert: %s\n", conf.Sf.Client.Certs_sf_accepts))
       
    router.router_ca_pool_when_acts_as_a_client, ok = makeCAPool(conf.Sf.Client.Certs_sf_accepts)
    if !ok {
        isErrorDetected = true
        router.Log(DEBUG, "    Result: FAILED\n")
    } else {
        router.Log(DEBUG, "    Result: OK\n")
    }

    if isErrorDetected {
        log.Fatal("An error occurred during certificates loading. See details in the log file.")
    }
}

// The Log() function writes messages from a provided slice as space-separated string into the log
func (router *Router) Log (logLevel int, messages ...string) {
    // Nothing to do, if message's log level is lower than those, user has set
    if logLevel < router.logLevel {
        return
    }
    
    // Creates a comma-separated string out of the incoming slice of strings
    s := router.logWriter.GetLogTimeStamp()
    for _, message := range messages {
        s = s + "," + message
    }
    
    // Send the resulting string to the logging channel
    router.logChannel <- []byte(s)
}


// The LogHTTPRequest() function prints HTTP request details into the log file
func (router *Router) LogHTTPRequest(logLevel int, req *http.Request) {

    // Check if we have anything to do
    if logLevel < router.logLevel {
        return
    }
    
    // Make a string to log
    t := time.Now()
    
    // Format time stamp
    ts := fmt.Sprintf("%d/%d/%d %02d:%02d:%02d ",
                       t.Year(),
                          t.Month(),
                             t.Day(),
                                t.Hour(),
                                     t.Minute(),
                                          t.Second())
                                           
    // Fill in the string with the rest data
    s := fmt.Sprintf("%s,%s,%s,%s,%t,%t,%s,success\n",
                      ts,
                         req.RemoteAddr,
                            req.TLS.ServerName,
                               matchTLSConst(req.TLS.Version),
                                  req.TLS.HandshakeComplete,
                                     req.TLS.DidResume,
                                        matchTLSConst(req.TLS.CipherSuite))
                                        
    // Write the string to the log file
    router.Log(logLevel, s)
}
