package service_function

import (
    "net/http"
    "fmt"
    "time"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    
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
    SFLOGGER_PRINT_TLS_INFO
    SFLOGGER_PRINT_TLS_PUBLIC_KEY
    SFLOGGER_PRINT_TLS_CERT_SIGNATURE
    SFLOGGER_PRINT_RAW
    SFLOGGER_PRINT_EMPTY_FIELDS
)


type ServiceFunction interface {
    ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool)
}

// Very simplistic example
type ServiceFunctionLogger struct {
    name string
    logWriter *logwriter.LogWriter
    logChannel chan []byte
    logLevel int
}

func NewServiceFunction() ServiceFunctionLogger {
    sf := new(ServiceFunctionLogger)
    sf.name = "logger"

    // Create a logging channel
    sf.logChannel = make(chan []byte, 256)

    // Create a new log writer
    sf.logWriter = logwriter.NewLogWriter(getLogFilePath, sf.logChannel, 5)

    // Run main loop of logWriter
    go sf.logWriter.Work()

    sf.Log(ALL, "============================================================\n")
    sf.Log(ALL, fmt.Sprintf("A service function \"%s\" has been created\n", sf.name))

    return *sf
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

// The Log() function writes messages from a provided slice as comma-separated string into the log file
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

    // Send the resulting string to the logging channel
    sf.logChannel <- []byte(s)
}


func (sf ServiceFunctionLogger) ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool) {
    var logLevel uint32
    
    LoggerHeaderName := "Sfloggerlevel"
    // fmt.Printf("req.Header[LoggerHeaderName] = %v\n", req.Header[LoggerHeaderName])
        
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
    // Change all 'fmt.Printf("%s", ' to 'sf.Log(ALL, '
    //

    if (logLevel & SFLOGGER_REGISTER_PACKETS_ONLY != 0) {
        addr, ok := req.Header["X-Forwarded-For"]
        if !ok {
            fmt.Printf("%s", fmt.Sprintf("%-32s: from %s to %s%s\n", "HTTP packet", req.RemoteAddr, req.Host, req.URL))
        } else {
            if (len(addr) > 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: from %s through %s to %s%s\n", "HTTP packet", addr[0], req.RemoteAddr, req.Host, req.URL))
            } else {
                fmt.Printf("%s", fmt.Sprintf("%-32s: from %s to %s%s\n", "HTTP packet", req.RemoteAddr, req.Host, req.URL))
            }
        }        
        forward = true
        return forward
    } 
    
    fmt.Printf("%s", fmt.Sprintf("%s\n", "======================= HTTP request ======================="))
    
    if (logLevel & SFLOGGER_PRINT_GENERAL_INFO != 0) {
        // sf.Log(ALL, fmt.Sprintf("%-32s: %s\n", "Method", req.Method))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %s\n", "Method", req.Method))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %s\n", "URL", req.URL))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %s\n", "Proto", req.Proto))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %d.%d\n", "Protocol Version", req.ProtoMajor, req.ProtoMinor))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %d byte(s)\n", "ContentLength", req.ContentLength))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "RemoteAddr", req.RemoteAddr))
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "RequestURI", req.RequestURI))
    }
    
    if (logLevel & SFLOGGER_PRINT_HEADER_FIELDS != 0) {
        for key, value := range req.Header {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Header." + key, value))
        }
    }
     


    if req.Body == http.NoBody {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: {}\n", "Body"))
        }
    } else {
        // ToDo: print Body
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Body", req.Body))
    }
    

    if req.GetBody == nil {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: <nil>\n", "GetBody"))
        }
    } else {
        // ToDo: print GetBody
        fmt.Printf("%s", fmt.Sprintf("%-32s: present (%v)\n", "GetBody", req.GetBody))
    }


    

    if len(req.TransferEncoding) == 0 {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "TransferEncoding"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "TransferEncoding"))
        for value := range req.TransferEncoding {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", value))
        }
    }

    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Close", req.Close))


    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Host", req.Host))


    // Allocate 32,5 MB for parsing the request MultipartForm
    req.ParseMultipartForm(32<<20 + 512)
    // ParseMultipartForm() includes a call of ParseForm()
    
    if len(req.Form) == 0 {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "Form"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Form", req.Form))
    }
    

    if len(req.PostForm) == 0 {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "PostForm"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "PostForm", req.PostForm))
    }
    
    
    if (req.MultipartForm == nil) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: <nil>\n", "MultipartForm"))
        }
    } else {
        if len(req.MultipartForm.Value) == 0 {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: map[]\n", "MultipartForm.Value"))
            }
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "MultipartForm.Value", req.MultipartForm.Value))
        }
        if len(req.MultipartForm.File) == 0 {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: map[]\n", "MultipartForm.File"))
            }
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "MultipartForm.File", req.MultipartForm.File))
        }
    }
    
    
    if (len(req.Trailer) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: map[]\n", "Trailer"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Trailer", req.Trailer))
    }



    if (logLevel & SFLOGGER_PRINT_TLS_INFO != 0) {
        if (req.TLS.Version >=769) && (req.TLS.Version <= 772) {
            fmt.Printf("%s", fmt.Sprintf("%-32s:  1.%d\n", "TLS.Version", req.TLS.Version-769))
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.Version", "WRONG VALUE!"))
        }
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.HandshakeComplete", req.TLS.HandshakeComplete))
        
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.DidResume", req.TLS.DidResume))
        
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.CipherSuite", tls.CipherSuiteName(req.TLS.CipherSuite)))
        
        if (len(req.TLS.NegotiatedProtocol) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: \"\"\n", "req.TLS.NegotiatedProtocol"))
            }
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.NegotiatedProtocol", req.TLS.NegotiatedProtocol))
        }        
        
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.NegotiatedProtocolIsMutual", req.TLS.NegotiatedProtocolIsMutual))
        
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.ServerName", req.TLS.ServerName))
        
        
        for i := range req.TLS.PeerCertificates {
            printCertInfo(req.TLS.PeerCertificates[i], fmt.Sprintf("TLS.PeerCertificates[%d]", i), logLevel)
        }
        
        
        if (len(req.TLS.VerifiedChains) > 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s  TLS.VerifiedChains:\n", "##############################"))
            for verifiedChainIndex := range req.TLS.VerifiedChains {
                for certIndex := range req.TLS.VerifiedChains[verifiedChainIndex] {
                    printCertInfo(req.TLS.VerifiedChains[verifiedChainIndex][certIndex], fmt.Sprintf("TLS.VerifiedChains[%d]:", certIndex), logLevel)
                }
            }
            fmt.Printf("%s", fmt.Sprintf("%-32s  End of TLS.VerifiedChains\n", "##############################"))
            
        } else {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s  TLS.VerifiedChains: []\n", "##############################"))
            } 
        }


        if (len(req.TLS.SignedCertificateTimestamps) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "TLS.SignedCertificateTimestamps"))
            }            
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "TLS.SignedCertificateTimestamps"))
            for _, s := range req.TLS.SignedCertificateTimestamps {
                fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", s))
            }
        }

        
        if (len(req.TLS.OCSPResponse) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "TLS.OCSPResponse"))
            }            
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.OCSPResponse", req.TLS.OCSPResponse))
        }
        
        if (len(req.TLS.TLSUnique) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "TLS.TLSUnique"))
            }            
        } else {
            fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "TLS.TLSUnique", req.TLS.TLSUnique))
        }
    }


    if (req.Cancel == nil) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: <nil>\n", "TLS.Cancel"))
        }            
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Cancel", req.Cancel))
    }

    if (req.Response == nil) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: <nil>\n", "TLS.Response"))
        }            
    } else {
        // ToDo: print Response
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "Response", req.Response))
    }

    forward = true
    return forward
}

func printCertInfo(cert *x509.Certificate, title string, logLevel uint32) {
    fmt.Printf("%s", fmt.Sprintf("%-32s  %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title))
    
    
    
    if (logLevel & SFLOGGER_PRINT_RAW != 0) {
      fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.Raw")))
      logRaw(cert.Raw)      
      
      fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawTBSCertificate")))
      logRaw(cert.RawTBSCertificate)
      
      if (logLevel & SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0) {
          fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawSubjectPublicKeyInfo")))
          logRaw(cert.RawSubjectPublicKeyInfo)
      }
      
      fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawSubject")))
      logRaw(cert.RawSubject)
      
      fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.RawIssuer")))
      logRaw(cert.RawIssuer)
      
      if (logLevel & SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0) {
          fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.Signature (raw)")))
          logRaw(cert.Signature)
      }
    }
    
    if (logLevel & SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0) {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.Signature", cert.Signature))
    }
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.SignatureAlgorithm", cert.SignatureAlgorithm))
    
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.PublicKeyAlgorithm", cert.PublicKeyAlgorithm))
    
    if (logLevel & SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0) {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v of type %T\n", "cert.PublicKey", cert.PublicKey, cert.PublicKey))
    }
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.Version", cert.Version))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.SerialNumber", cert.SerialNumber))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.Issuer", cert.Issuer))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.Subject", cert.Subject))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.NotBefore", cert.NotBefore))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.NotAfter", cert.NotAfter))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.KeyUsage", cert.KeyUsage))
    
    
    if (len(cert.Extensions) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.Extensions"))
        }
    } else {
        for i := range cert.Extensions {
            fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.Extensions[%d]",i)))
            printExtensionInfo(cert.Extensions[i], logLevel)
        }
    }
    
    
    if (len(cert.ExtraExtensions) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.ExtraExtensions"))
        }
    } else {
        for i := range cert.ExtraExtensions {
            fmt.Printf("%s", fmt.Sprintf("%-32s:\n", fmt.Sprintf("cert.ExtraExtensions[%d]",i)))
            printExtensionInfo(cert.ExtraExtensions[i], logLevel)
        }
    }
    
    
    if (len(cert.UnhandledCriticalExtensions) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.UnhandledCriticalExtensions"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "UnhandledCriticalExtensions", cert.UnhandledCriticalExtensions))
    }
    
    
    if (len(cert.ExtKeyUsage) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.ExtKeyUsage"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "ExtKeyUsage", cert.ExtKeyUsage))
    }
    
    
    if (len(cert.UnknownExtKeyUsage) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.UnknownExtKeyUsage"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.UnknownExtKeyUsage", cert.UnknownExtKeyUsage))
    }
    
   
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.BasicConstraintsValid", cert.BasicConstraintsValid))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.IsCA", cert.IsCA))
    
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.MaxPathLen", cert.MaxPathLen))
    
    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.MaxPathLenZero", cert.MaxPathLenZero))
    
    
    
    if (len(cert.SubjectKeyId) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.SubjectKeyId"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.SubjectKeyId", cert.SubjectKeyId))
    }
    
    
    if (len(cert.AuthorityKeyId) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.AuthorityKeyId"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.AuthorityKeyId", cert.AuthorityKeyId))
    }
    
    
    if (len(cert.OCSPServer) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.OCSPServer"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "cert.OCSPServers"))
        for i := range cert.OCSPServer {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", cert.OCSPServer[i]))
        }
    }
    
    if (len(cert.IssuingCertificateURL) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.IssuingCertificateURL"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "cert.OCSPServers"))
        for i := range cert.IssuingCertificateURL {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", cert.IssuingCertificateURL[i]))
        }
    }
    
    
    if (len(cert.DNSNames) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.DNSNames"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "cert.DNSNames"))
        for i := range cert.DNSNames {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", cert.DNSNames[i]))
        }
    }
    
    if (len(cert.EmailAddresses) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.EmailAddresses"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "cert.EmailAddresses"))
        for i := range cert.EmailAddresses {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", cert.EmailAddresses[i]))
        }
    }
    
    
    if (len(cert.IPAddresses) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.IPAddresses"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "cert.IPAddresses"))
        for i := range cert.IPAddresses {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", cert.IPAddresses[i]))
        }
    }
    
    if (len(cert.URIs) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.URIs"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", "cert.URIs"))
        for i := range cert.URIs {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", cert.URIs[i]))
        }
    }

    fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.PermittedDNSDomainsCritical", cert.PermittedDNSDomainsCritical))
    
    logSliceStrings(cert.PermittedDNSDomains, "cert.PermittedDNSDomains", logLevel)
    
    logSliceStrings(cert.ExcludedDNSDomains, "cert.ExcludedDNSDomains", logLevel)
    
    if (len(cert.PermittedIPRanges) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.PermittedIPRanges"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.PermittedIPRanges", cert.PermittedIPRanges))
    }
    
    
    if (len(cert.ExcludedIPRanges) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.ExcludedIPRanges"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.ExcludedIPRanges", cert.ExcludedIPRanges))
    }
   

    logSliceStrings(cert.PermittedEmailAddresses, "cert.PermittedEmailAddresses", logLevel)
    
    logSliceStrings(cert.ExcludedEmailAddresses, "cert.ExcludedEmailAddresses", logLevel)
    
    logSliceStrings(cert.PermittedURIDomains, "cert.PermittedURIDomains", logLevel)
    
    logSliceStrings(cert.ExcludedURIDomains, "cert.ExcludedURIDomains", logLevel)
    
    
    logSliceStrings(cert.CRLDistributionPoints, "cert.CRLDistributionPoints", logLevel)
    
    if (len(cert.PolicyIdentifiers) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", "cert.PolicyIdentifiers"))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s: %v\n", "cert.PolicyIdentifiers", cert.PolicyIdentifiers))
    }
    
    fmt.Printf("%s", fmt.Sprintf("%-32s  End of %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title))
    return
}

func printExtensionInfo(ext pkix.Extension, logLevel uint32) {
    fmt.Printf("%s", fmt.Sprintf("%-32s  Id:          %v\n", "", ext.Id))
    fmt.Printf("%s", fmt.Sprintf("%-32s  Critical:    %v\n", "", ext.Critical))
    fmt.Printf("%s", fmt.Sprintf("%-32s  Value:       %s\n", "", string(ext.Value)))    
    if (logLevel & SFLOGGER_PRINT_RAW != 0) {
        fmt.Printf("%s", fmt.Sprintf("%-32s  Value (raw): %v\n", "", ext.Value))    
    }
    return
}


func logSliceBytes(data []byte, name string, logLevel uint32) {
    if (len(data) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", name))
        }
    } else {
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", name))
        for i := range data {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", data[i]))
        }
    }
}

func logSliceStrings(data []string, name string, logLevel uint32) {
    if (len(data) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            fmt.Printf("%s", fmt.Sprintf("%-32s: []\n", name))
        }
    } else {                                                                                                                                                                                                                                                                                                                                                  
        fmt.Printf("%s", fmt.Sprintf("%-32s:\n", name))
        for i := range data {
            fmt.Printf("%s", fmt.Sprintf("%-32s  - %v\n", "", data[i]))
        }
    }
}

func logRaw(data []byte) {
    // Number of complete lines
    numLines := int(len(data) / 32)
    
    // Printf all lines as 16 + 16 hex symbols
    for i := 0; i < numLines-1; i++ {
        
        // Left indentation
        fmt.Printf("%s", fmt.Sprintf("%-32s  ", ""))
        for j := 0; j < 16; j++ {
            fmt.Printf("%s", fmt.Sprintf("%02X ", data[i * 32 + j]))
        }
        
        // Space between two columns
        fmt.Printf("%s", fmt.Sprintf("%s  ", ""))
        for j := 0; j < 16; j++ {
            fmt.Printf("%s", fmt.Sprintf("%02X ", data[i * 32 + 16 + j]))
        }
        
        // Next line at the end
        fmt.Printf("%s", fmt.Sprintf("\n"))
    }
    
    // Last line has 1-31 symbol(s)
    // Left indentation
    fmt.Printf("%s", fmt.Sprintf("%-32s  ", ""))

    // If the last symbol is in the first column
    if (len(data) - numLines * 32 <= 16) {
        for j := 0; j < len(data) - numLines * 32; j++ {
            fmt.Printf("%s", fmt.Sprintf("%02X ", data[numLines * 32 + j]))
        }
    // }
    } else {
    // If the last symbol is in the second column
        for j := 0; j < 16; j++ {
            fmt.Printf("%s", fmt.Sprintf("%02X ", data[numLines * 32 + j]))
        }
        fmt.Printf("%s", fmt.Sprintf("%s  ", ""))
        for j := 0; j < len(data) - numLines * 32 - 16; j++ {
            fmt.Printf("%s", fmt.Sprintf("%02X ", data[numLines * 32 + 16 + j]))
        }
    }
    
    // Next line at the end of the raw output
    fmt.Printf("%s", fmt.Sprintf("%s\n", ""))
}