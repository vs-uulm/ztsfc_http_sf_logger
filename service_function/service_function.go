package service_function

import (
    "net/http"
    "fmt"
    "time"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "bytes"
    "io/ioutil"
    "mime/multipart"
    "bufio"
    "log"
    
    "strconv"
    
    "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
)

const (
    NONE = iota
    BASIC
    ADVANCED
    DEBUG
    ALL
)

const (
    SFLOGGER_REGISTER_PACKETS_ONLY  uint32  = 1 << iota
    SFLOGGER_PRINT_GENERAL_INFO
    SFLOGGER_PRINT_HEADER_FIELDS
    SFLOGGER_PRINT_TRAILERS
    SFLOGGER_PRINT_BODY
    SFLOGGER_PRINT_FORMS
    SFLOGGER_PRINT_FORMS_FILE_CONTENT
    SFLOGGER_PRINT_TLS_MAIN_INFO
    SFLOGGER_PRINT_TLS_CERTIFICATES
    SFLOGGER_PRINT_TLS_PUBLIC_KEY
    SFLOGGER_PRINT_TLS_CERT_SIGNATURE
    SFLOGGER_PRINT_RAW
    SFLOGGER_PRINT_REDIRECTED_RESPONSE
    SFLOGGER_PRINT_EMPTY_FIELDS
)

type ServiceFunction interface {
    ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool)
}

type ServiceFunctionLogger struct {
    name string
    logWriter *logwriter.LogWriter
    logChannel chan []byte
    logLevel int
    logToFile bool
}

func NewServiceFunction() ServiceFunctionLogger {
    sf := new(ServiceFunctionLogger)
    sf.name = "logger"
    sf.logToFile = false

    // Create a logging channel
    sf.logChannel = make(chan []byte, 256)

    // Create a new log writer
    sf.logWriter = logwriter.NewLogWriter(getLogFilePath, sf.logChannel, 5)

    // Run main loop of logWriter
    go sf.logWriter.Work()

    return *sf
}

func (sf *ServiceFunctionLogger) SetOptions(_logToFile bool) {
    sf.logToFile = _logToFile
    sf.Log(ALL, "============================================================\n")
    sf.Log(ALL, fmt.Sprintf("A service function \"%s\" has been created\n", sf.name))
}

func getLogFilePath() string {
    t := time.Now()

    // Format time stamp
    ts := fmt.Sprintf("sf-logger-%4d-%02d-%02d-%02d.log",
                                 t.Year(),
                                     t.Month(),
                                          t.Day(),
                                               t.Hour())
    return ts
}

// The Log() function writes messages from a provided slice as comma-separated string
// either into the log file or output it to the screen
func (sf *ServiceFunctionLogger) Log (logLevel int, messages ...string) {
    // Nothing to do, if message's log level is lower than those, user has set
    if logLevel < sf.logLevel {
        return
    }
    
    // Creates a comma-separated string out of the incoming slice of strings
    s := sf.logWriter.GetLogTimeStamp()
    for _, message := range messages {
        s = s + "," + message
    }
    
    if sf.logToFile {
        // Send the resulting string to the logging channel
        sf.logChannel <- []byte(s)
    } else {
        // Print the resulting string to the screen
        fmt.Print(s)
    }
}


func (sf ServiceFunctionLogger) ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool) {
    var logLevel uint32
    
    LoggerHeaderName := "Sfloggerlevel"

    logLevelString, ok := req.Header[LoggerHeaderName]
    if ok {
        req.Header.Del(LoggerHeaderName)
        u64, err := strconv.ParseUint(logLevelString[0], 10, 32) 
        if err != nil {
            fmt.Println(err)
        }
        logLevel = uint32(u64)
    } else {
        logLevel = SFLOGGER_REGISTER_PACKETS_ONLY
    }


    //
    // SFLOGGER_REGISTER_PACKETS_ONLY
    //

    if (logLevel & SFLOGGER_REGISTER_PACKETS_ONLY != 0) {
        addr, ok := req.Header["X-Forwarded-For"]
        if !ok {
            sf.Log(ALL, fmt.Sprintf("%-32s: from %s to %s%s\n", "HTTP packet", req.RemoteAddr, req.Host, req.URL))
        } else {
            if (len(addr) > 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: from %s through %s to %s%s\n", "HTTP packet", addr[0], req.RemoteAddr, req.Host, req.URL))
            } else {
                sf.Log(ALL, fmt.Sprintf("%-32s: from %s to %s%s\n", "HTTP packet", req.RemoteAddr, req.Host, req.URL))
            }
        }
        forward = true
        return forward
    } 

    sf.Log(ALL, fmt.Sprintf("%s\n", "======================= HTTP request ======================="))

    //
    // SFLOGGER_PRINT_GENERAL_INFO
    //

    if (logLevel & SFLOGGER_PRINT_GENERAL_INFO != 0) {
        sf.Log(ALL, fmt.Sprintf("%-32s: %s\n", "Method", req.Method))
        sf.Log(ALL, fmt.Sprintf("%-32s: %s\n", "URL", req.URL))
        sf.Log(ALL, fmt.Sprintf("%-32s: %s\n", "Proto", req.Proto))
        sf.Log(ALL, fmt.Sprintf("%-32s: %d.%d\n", "Protocol Version", req.ProtoMajor, req.ProtoMinor))
        sf.Log(ALL, fmt.Sprintf("%-32s: %d byte(s)\n", "ContentLength", req.ContentLength))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "RemoteAddr", req.RemoteAddr))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "RequestURI", req.RequestURI))
        
        if len(req.TransferEncoding) == 0 {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "TransferEncoding"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "TransferEncoding"))
            for value := range req.TransferEncoding {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", value))
            }
        }    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Close", req.Close))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Host", req.Host))

        if (req.Cancel == nil) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: <nil>\n", "TLS.Cancel"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Cancel", req.Cancel))
        }
    }
    
    //
    // SFLOGGER_PRINT_HEADER_FIELDS
    //

    if (logLevel & SFLOGGER_PRINT_HEADER_FIELDS != 0) {
        for key, value := range req.Header {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Header." + key, value))
        }
    }
     

    //
    // SFLOGGER_PRINT_BODY
    //

    if (logLevel & SFLOGGER_PRINT_BODY != 0) {
        if req.Body == http.NoBody {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: {}\n", "Body"))
            }
        } else {
            // ToDo: print Body
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Body", req.Body))
        }
        

        if req.GetBody == nil {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: <nil>\n", "GetBody"))
            }
        } else {
            // ToDo: print GetBody
            sf.Log(ALL, fmt.Sprintf("%-32s: present (%v)\n", "GetBody", req.GetBody))
        }
    }

    //
    // SFLOGGER_PRINT_FORMS
    //

    if (logLevel & SFLOGGER_PRINT_FORMS != 0) {
    
        // Manually save the request body
        body, err := ioutil.ReadAll(req.Body)
        if err != nil {
            fmt.Printf("[Router.ServeHTTP]: Can't manually read the request body: ", err)
            return
        }
        
        req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
        
        // create a new request for parsing the body
        req2, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
        req2.Header = req.Header
        
        // Allocate 32,5 MB for parsing the req2uest MultipartForm
        // ParseMultipartForm() includes a call of ParseForm()
        req2.ParseMultipartForm(32<<20 + 512)
        
        if len(req2.Form) == 0 {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "Form"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Form", req2.Form))
        }
        

        if len(req2.PostForm) == 0 {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "PostForm"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "PostForm", req2.PostForm))
        }
        
        
        if (req2.MultipartForm == nil) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: <nil>\n", "MultipartForm"))
            }
        } else {
            if len(req2.MultipartForm.Value) == 0 {
                if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                    sf.Log(ALL, fmt.Sprintf("%-32s: map[]\n", "MultipartForm.Value"))
                }
            } else {
                sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "MultipartForm.Value", req2.MultipartForm.Value))
            }
            if len(req2.MultipartForm.File) == 0 {
                if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                    sf.Log(ALL, fmt.Sprintf("%-32s: map[]\n", "MultipartForm.File"))
                }
            } else {
                for k, v := range req2.MultipartForm.File {
                    sf.Log(ALL, fmt.Sprintf("%-32s: \"%v\"\n", "MultipartForm.File", k))
                    var fh multipart.FileHeader
                    for _, fhp := range v {
                        fh = *fhp
                        fmt.Printf("  Filename = %v\n", fh.Filename)
                        fmt.Printf("  Size     = %v\n", fh.Size)
                        fmt.Printf("  Header   = \n")
                        for hk, hvalues := range fh.Header {
                            fmt.Printf("    MIMEHeader[%v] :\n", hk)
                            for _, hv  := range hvalues {
                                fmt.Printf("      - %v\n", hv)
                            }
                        }
                        
                        //
                        // SFLOGGER_PRINT_FORMS_FILE_CONTENT
                        //

                        if (logLevel & SFLOGGER_PRINT_FORMS_FILE_CONTENT != 0) {                        
                            file, err := fh.Open()
                            if err !=nil {
                                fmt.Printf("Could not open the file \"%v\". Error: %v", k, err)
                                return
                            } else {
                                fmt.Printf("    File \"%v\" content:\n", k)
                                defer file.Close()
                                
                                scanner := bufio.NewScanner(file)
                                for scanner.Scan() {
                                    fmt.Printf("      |%v\n",scanner.Text())
                                }

                                if err := scanner.Err(); err != nil {
                                    log.Fatal(err)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    //
    // SFLOGGER_PRINT_TRAILERS
    //

    if (logLevel & SFLOGGER_PRINT_TRAILERS != 0) {    
        if (len(req.Trailer) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: map[]\n", "Trailer"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Trailer", req.Trailer))
        }
    }


    //
    // SFLOGGER_PRINT_TLS_MAIN_INFO
    //

    if (logLevel & SFLOGGER_PRINT_TLS_MAIN_INFO != 0) {
        if (req.TLS.Version >=769) && (req.TLS.Version <= 772) {
            sf.Log(ALL, fmt.Sprintf("%-32s: 1.%d\n", "TLS.Version", req.TLS.Version-769))
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.Version", "WRONG VALUE!"))
        }
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.HandshakeComplete", req.TLS.HandshakeComplete))
        
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.DidResume", req.TLS.DidResume))
        
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.CipherSuite", tls.CipherSuiteName(req.TLS.CipherSuite)))
        
        if (len(req.TLS.NegotiatedProtocol) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: \"\"\n", "req.TLS.NegotiatedProtocol"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.NegotiatedProtocol", req.TLS.NegotiatedProtocol))
        }        
        
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.NegotiatedProtocolIsMutual", req.TLS.NegotiatedProtocolIsMutual))
        
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.ServerName", req.TLS.ServerName))
        
        
        
        if (len(req.TLS.SignedCertificateTimestamps) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "TLS.SignedCertificateTimestamps"))
            }            
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "TLS.SignedCertificateTimestamps"))
            for _, s := range req.TLS.SignedCertificateTimestamps {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", s))
            }
        }

        
        if (len(req.TLS.OCSPResponse) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "TLS.OCSPResponse"))
            }            
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.OCSPResponse", req.TLS.OCSPResponse))
        }
        
        if (len(req.TLS.TLSUnique) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "TLS.TLSUnique"))
            }            
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "TLS.TLSUnique", req.TLS.TLSUnique))
        }
    }
    
    
    //
    // SFLOGGER_PRINT_TLS_CERTIFICATES
    //

    for i := range req.TLS.PeerCertificates {
        sf.printCertInfo(req.TLS.PeerCertificates[i], fmt.Sprintf("TLS.PeerCertificates[%d]", i), logLevel)
    }
    
    if (len(req.TLS.VerifiedChains) > 0) {
        for verifiedChainIndex := range req.TLS.VerifiedChains {
            for certIndex := range req.TLS.VerifiedChains[verifiedChainIndex] {
                sf.printCertInfo(req.TLS.VerifiedChains[verifiedChainIndex][certIndex], fmt.Sprintf("TLS.VerifiedChains[%d]:", certIndex), logLevel)
            }
        }
    } else {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.Log(ALL, fmt.Sprintf("%-32s  TLS.VerifiedChains: []\n", ""))
        } 
    }

    //
    // SFLOGGER_PRINT_REDIRECTED_RESPONSE
    //

    if (logLevel & SFLOGGER_PRINT_REDIRECTED_RESPONSE != 0) {
        if (req.Response == nil) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: <nil>\n", "TLS.Response"))
            }
        } else {
            // ToDo: print Response
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "Response", req.Response))
        }
    }

    forward = true
    return forward
}

func (sf ServiceFunctionLogger) printCertInfo(cert *x509.Certificate, title string, logLevel uint32) {
    sf.Log(ALL, fmt.Sprintf("%-32s  %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title))

    //
    // SFLOGGER_PRINT_TLS_MAIN_INFO
    //

    if (logLevel & SFLOGGER_PRINT_TLS_MAIN_INFO != 0) {
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.SignatureAlgorithm", cert.SignatureAlgorithm))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.PublicKeyAlgorithm", cert.PublicKeyAlgorithm))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.Version", cert.Version))    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.SerialNumber", cert.SerialNumber))    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.Issuer", cert.Issuer))    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.Subject", cert.Subject))    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.NotBefore", cert.NotBefore))    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.NotAfter", cert.NotAfter))    
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.KeyUsage", cert.KeyUsage))
        
        if (len(cert.Extensions) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.Extensions"))
            }
        } else {
            for i := range cert.Extensions {
                sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.Extensions[%d]",i)))
                sf.printExtensionInfo(cert.Extensions[i], logLevel)
            }
        }
        
        
        if (len(cert.ExtraExtensions) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.ExtraExtensions"))
            }
        } else {
            for i := range cert.ExtraExtensions {
                sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.ExtraExtensions[%d]",i)))
                sf.printExtensionInfo(cert.ExtraExtensions[i], logLevel)
            }
        }
        
        
        if (len(cert.UnhandledCriticalExtensions) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.UnhandledCriticalExtensions"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "UnhandledCriticalExtensions", cert.UnhandledCriticalExtensions))
        }
        
        
        if (len(cert.ExtKeyUsage) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.ExtKeyUsage"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "ExtKeyUsage", cert.ExtKeyUsage))
        }
        
        
        if (len(cert.UnknownExtKeyUsage) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.UnknownExtKeyUsage"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.UnknownExtKeyUsage", cert.UnknownExtKeyUsage))
        }
        
       
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.BasicConstraintsValid", cert.BasicConstraintsValid))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.IsCA", cert.IsCA))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.MaxPathLen", cert.MaxPathLen))
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.MaxPathLenZero", cert.MaxPathLenZero))
        
        if (len(cert.SubjectKeyId) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.SubjectKeyId"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.SubjectKeyId", cert.SubjectKeyId))
        }
        
        
        if (len(cert.AuthorityKeyId) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.AuthorityKeyId"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.AuthorityKeyId", cert.AuthorityKeyId))
        }
        
        
        if (len(cert.OCSPServer) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.OCSPServer"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "cert.OCSPServers"))
            for i := range cert.OCSPServer {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", cert.OCSPServer[i]))
            }
        }
        
        if (len(cert.IssuingCertificateURL) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.IssuingCertificateURL"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "cert.OCSPServers"))
            for i := range cert.IssuingCertificateURL {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", cert.IssuingCertificateURL[i]))
            }
        }
        
        
        if (len(cert.DNSNames) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.DNSNames"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "cert.DNSNames"))
            for i := range cert.DNSNames {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", cert.DNSNames[i]))
            }
        }
        
        if (len(cert.EmailAddresses) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.EmailAddresses"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "cert.EmailAddresses"))
            for i := range cert.EmailAddresses {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", cert.EmailAddresses[i]))
            }
        }
        
        
        if (len(cert.IPAddresses) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.IPAddresses"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "cert.IPAddresses"))
            for i := range cert.IPAddresses {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", cert.IPAddresses[i]))
            }
        }
        
        if (len(cert.URIs) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.URIs"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", "cert.URIs"))
            for i := range cert.URIs {
                sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", cert.URIs[i]))
            }
        }

        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.PermittedDNSDomainsCritical", cert.PermittedDNSDomainsCritical))
        
        sf.logSliceStrings(cert.PermittedDNSDomains, "cert.PermittedDNSDomains", logLevel)
        
        sf.logSliceStrings(cert.ExcludedDNSDomains, "cert.ExcludedDNSDomains", logLevel)
        
        if (len(cert.PermittedIPRanges) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.PermittedIPRanges"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.PermittedIPRanges", cert.PermittedIPRanges))
        }
        
        
        if (len(cert.ExcludedIPRanges) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.ExcludedIPRanges"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.ExcludedIPRanges", cert.ExcludedIPRanges))
        }
       

        sf.logSliceStrings(cert.PermittedEmailAddresses, "cert.PermittedEmailAddresses", logLevel)
        
        sf.logSliceStrings(cert.ExcludedEmailAddresses, "cert.ExcludedEmailAddresses", logLevel)
        
        sf.logSliceStrings(cert.PermittedURIDomains, "cert.PermittedURIDomains", logLevel)
        
        sf.logSliceStrings(cert.ExcludedURIDomains, "cert.ExcludedURIDomains", logLevel)
        
        
        sf.logSliceStrings(cert.CRLDistributionPoints, "cert.CRLDistributionPoints", logLevel)
        
        if (len(cert.PolicyIdentifiers) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.Log(ALL, fmt.Sprintf("%-32s: []\n", "cert.PolicyIdentifiers"))
            }
        } else {
            sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.PolicyIdentifiers", cert.PolicyIdentifiers))
        }
    }
    
    //
    // SFLOGGER_PRINT_RAW
    //

    if (logLevel & SFLOGGER_PRINT_RAW != 0) {
        sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.Raw")))
        sf.logRaw(cert.Raw)      
        
        sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawTBSCertificate")))
        sf.logRaw(cert.RawTBSCertificate)
        
        if (logLevel & SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0) {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawSubjectPublicKeyInfo")))
            sf.logRaw(cert.RawSubjectPublicKeyInfo)
        }
        
        sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawSubject")))
        sf.logRaw(cert.RawSubject)
        
        sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawIssuer")))
        sf.logRaw(cert.RawIssuer)
        
        if (logLevel & SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0) {
            sf.Log(ALL, fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.Signature (raw)")))
            sf.logRaw(cert.Signature)
        }
    }
    
    //
    // SFLOGGER_PRINT_TLS_CERT_SIGNATURE
    //

    if (logLevel & SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0) {
        sf.Log(ALL, fmt.Sprintf("%-32s: %v\n", "cert.Signature", cert.Signature))
    }
    
    
    //
    // SFLOGGER_PRINT_TLS_PUBLIC_KEY
    //

    if (logLevel & SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0) {
        sf.Log(ALL, fmt.Sprintf("%-32s: %v of type %T\n", "cert.PublicKey", cert.PublicKey, cert.PublicKey))
    }
    
    sf.Log(ALL, fmt.Sprintf("%-32s  End of %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title))
    return
}

func (sf ServiceFunctionLogger) printExtensionInfo(ext pkix.Extension, logLevel uint32) {
    sf.Log(ALL, fmt.Sprintf("%-32s  Id:          %v\n", "", ext.Id))
    sf.Log(ALL, fmt.Sprintf("%-32s  Critical:    %v\n", "", ext.Critical))
    sf.Log(ALL, fmt.Sprintf("%-32s  Value:       %s\n", "", string(ext.Value)))    
    sf.Log(ALL, fmt.Sprintf("%-32s  Value (raw): %v\n", "", ext.Value))    
    return
}


func (sf ServiceFunctionLogger) logSliceBytes(data []byte, name string, logLevel uint32) {
    if (len(data) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.Log(ALL, fmt.Sprintf("%-32s: []\n", name))
        }
    } else {
        sf.Log(ALL, fmt.Sprintf("%-32s:\n", name))
        for i := range data {
            sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", data[i]))
        }
    }
}

func (sf ServiceFunctionLogger) logSliceStrings(data []string, name string, logLevel uint32) {
    if (len(data) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.Log(ALL, fmt.Sprintf("%-32s: []\n", name))
        }
    } else {                                                                                                                                                                                                                                                                                                                                                  
        sf.Log(ALL, fmt.Sprintf("%-32s:\n", name))
        for i := range data {
            sf.Log(ALL, fmt.Sprintf("%-32s  - %v\n", "", data[i]))
        }
    }
}

func (sf ServiceFunctionLogger) logRaw(data []byte) {
    // Number of complete lines
    numLines := int(len(data) / 32)
    
    // Printf all lines as 16 + 16 hex symbols
    for i := 0; i < numLines-1; i++ {
        
        // Left indentation
        sf.Log(ALL, fmt.Sprintf("%-32s  ", ""))
        for j := 0; j < 16; j++ {
            sf.Log(ALL, fmt.Sprintf("%02X ", data[i * 32 + j]))
        }
        
        // Space between two columns
        sf.Log(ALL, fmt.Sprintf("%s  ", ""))
        for j := 0; j < 16; j++ {
            sf.Log(ALL, fmt.Sprintf("%02X ", data[i * 32 + 16 + j]))
        }
        
        // Next line at the end
        sf.Log(ALL, fmt.Sprintf("\n"))
    }
    
    // Last line has 1-31 symbol(s)
    // Left indentation
    sf.Log(ALL, fmt.Sprintf("%-32s  ", ""))

    // If the last symbol is in the first column
    if (len(data) - numLines * 32 <= 16) {
        for j := 0; j < len(data) - numLines * 32; j++ {
            sf.Log(ALL, fmt.Sprintf("%02X ", data[numLines * 32 + j]))
        }
    // }
    } else {
    // If the last symbol is in the second column
        for j := 0; j < 16; j++ {
            sf.Log(ALL, fmt.Sprintf("%02X ", data[numLines * 32 + j]))
        }
        sf.Log(ALL, fmt.Sprintf("%s  ", ""))
        for j := 0; j < len(data) - numLines * 32 - 16; j++ {
            sf.Log(ALL, fmt.Sprintf("%02X ", data[numLines * 32 + 16 + j]))
        }
    }
    
    // Next line at the end of the raw output
    sf.Log(ALL, fmt.Sprintf("%s\n", ""))
}