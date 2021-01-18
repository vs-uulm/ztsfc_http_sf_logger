package service_function

import (
    "net/http"
    "fmt"
    "time"
    "crypto/tls"
    "crypto/x509"
    
    "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
)

const (
    NONE = iota
    BASIC
    ADVANCED
    DEBUG
    ALL
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
    fmt.Printf("\n+++ ApplyFunction +++\nRequest: %+v\n\n", req)

    //
    // Change all 'fmt.Printf("%s", ' by 'sf.Log(ALL, '
    //

    fmt.Printf("%s", "======================= HTTP request =======================\n")

    fmt.Printf("--->> %20s", "Method\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %s\n", "Method", req.Method))
    // sf.Log(ALL, fmt.Sprintf("%30s: %s\n", "Method", req.Method))
    
    fmt.Printf("--->> %20s", "URL\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %s\n", "URL", req.URL))
    
    fmt.Printf("--->> %20s", "Proto\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %s\n", "Proto", req.Proto))

    fmt.Printf("--->> %20s", "ProtoMajor\n")
    fmt.Printf("--->> %20s", "ProtoMinor\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %d.%d\n", "Protocol Version", req.ProtoMajor, req.ProtoMinor))

    fmt.Printf("--->> %20s", "Header\n")
    for key, value := range req.Header {
        fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", key, value))
    }


    fmt.Printf("--->> %20s", "Body\n")
    if req.Body == http.NoBody {
        fmt.Printf("%s", fmt.Sprintf("%30s: {}\n", "Body"))
    } else {
        // ToDo: print Body
        fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Body", req.Body))
    }


    fmt.Printf("--->> %20s", "GetBody()\n")
    if req.GetBody == nil {
        fmt.Printf("%s", fmt.Sprintf("%30s: <nil>\n", "GetBody"))
    } else {
        // ToDo: print GetBody
        fmt.Printf("%s", fmt.Sprintf("%30s: present (%v)\n", "GetBody", req.GetBody))
    }
    

    fmt.Printf("--->> %20s", "ContentLength\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %d byte(s)\n", "ContentLength", req.ContentLength))
    
    fmt.Printf("--->> %20s", "TransferEncoding\n")
    if len(req.TransferEncoding) == 0 {
        fmt.Printf("%s", fmt.Sprintf("%30s: []\n", "TransferEncoding"))
    } else {
        fmt.Printf("%s", fmt.Sprintf("%30s:\n", "TransferEncoding"))
        for value := range req.TransferEncoding {
            fmt.Printf("%s", fmt.Sprintf("%30s  - %v\n", "", value))
        }
    }

    
    fmt.Printf("--->> %20s", "Close\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Close", req.Close))
    
    fmt.Printf("--->> %20s", "Host\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Host", req.Host))

    fmt.Printf("--->> %20s", "Form\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Form", req.Form))

    fmt.Printf("--->> %20s", "PostForm\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "PostForm", req.PostForm))

    fmt.Printf("--->> %20s", "MultipartForm\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "MultipartForm", req.MultipartForm))

    fmt.Printf("--->> %20s", "Trailer\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Trailer", req.Trailer))

    fmt.Printf("--->> %20s", "RemoteAddr\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "RemoteAddr", req.RemoteAddr))

    fmt.Printf("--->> %20s", "RequestURI\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "RequestURI", req.RequestURI))

    fmt.Printf("--->> %20s", "TLS\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS", req.TLS))
    if (req.TLS.Version >=769) && (req.TLS.Version <= 772) {
        fmt.Printf("%s", fmt.Sprintf("%30s:  1.%d\n", "TLS.Version", req.TLS.Version-769))
    } else {
        fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.Version", "WRONG VALUE!"))
    }
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.HandshakeComplete", req.TLS.HandshakeComplete))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.DidResume", req.TLS.DidResume))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.CipherSuite", tls.CipherSuiteName(req.TLS.CipherSuite)))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.NegotiatedProtocol", req.TLS.NegotiatedProtocol))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.NegotiatedProtocolIsMutual", req.TLS.NegotiatedProtocolIsMutual))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.ServerName", req.TLS.ServerName))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.PeerCertificates", req.TLS.PeerCertificates))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v of type %T\n", "TLS.PeerCertificates", req.TLS.PeerCertificates, req.TLS.PeerCertificates))
    
    for i := range req.TLS.PeerCertificates {
        printCertInfo(req.TLS.PeerCertificates[i], fmt.Sprintf("TLS.PeerCertificates[%d]", i))
    }
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.VerifiedChains", req.TLS.VerifiedChains))
    
    if (len(req.TLS.VerifiedChains) > 0) {
        fmt.Printf("%s", fmt.Sprintf("%30s TLS.VerifiedChains:\n", "##############################"))
        for verifiedChainIndex := range req.TLS.VerifiedChains {
            for certIndex := range req.TLS.VerifiedChains[verifiedChainIndex] {
                printCertInfo(req.TLS.VerifiedChains[verifiedChainIndex][certIndex], fmt.Sprintf("TLS.VerifiedChains[%d] info:", certIndex))
            }
        }
        fmt.Printf("%s", fmt.Sprintf("%30s End of TLS.VerifiedChains\n", "##############################"))
        
    } else {
        fmt.Printf("%s", fmt.Sprintf("%30s TLS.VerifiedChains: []\n", "##############################"))
    }
    
    
    
    
    if (len(req.TLS.SignedCertificateTimestamps) == 0) {
        fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.SignedCertificateTimestamps", req.TLS.SignedCertificateTimestamps))
    } else {
        fmt.Printf("%s", fmt.Sprintf("%30s:\n", "TLS.SignedCertificateTimestamps"))
        for _, s := range req.TLS.SignedCertificateTimestamps {
            fmt.Printf("%s", fmt.Sprintf("%30s  - %v\n", "", s))
        }
    }

    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.OCSPResponse", req.TLS.OCSPResponse))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "TLS.TLSUnique", req.TLS.TLSUnique))
    
    

















    fmt.Printf("--->> %20s", "Cancel\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Cancel", req.Cancel))

    fmt.Printf("--->> %20s", "Response\n")
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "Response", req.Response))




    
    
    
    
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







    forward = true
    return forward
}

func printCertInfo(cert *x509.Certificate, title string) {
    fmt.Printf("%s", fmt.Sprintf("%30s %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.Raw", cert.Raw))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.RawTBSCertificate", cert.RawTBSCertificate))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.RawSubjectPublicKeyInfo", cert.RawSubjectPublicKeyInfo))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.RawSubject", cert.RawSubject))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.RawIssuer", cert.RawIssuer))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.Signature", cert.Signature))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.SignatureAlgorithm", cert.SignatureAlgorithm))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PublicKeyAlgorithm", cert.PublicKeyAlgorithm))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PublicKey", cert.PublicKey))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.Version", cert.Version))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.SerialNumber", cert.SerialNumber))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.Issuer", cert.Issuer))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.Subject", cert.Subject))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.NotBefore", cert.NotBefore))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.NotAfter", cert.NotAfter))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.KeyUsage", cert.KeyUsage))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.Extensions", cert.Extensions))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.ExtraExtensions", cert.ExtraExtensions))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.UnhandledCriticalExtensions", cert.UnhandledCriticalExtensions))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.ExtKeyUsage", cert.ExtKeyUsage))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.UnknownExtKeyUsage", cert.UnknownExtKeyUsage))
    
   
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.BasicConstraintsValid", cert.BasicConstraintsValid))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.IsCA", cert.IsCA))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.MaxPathLen", cert.MaxPathLen))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.MaxPathLenZero", cert.MaxPathLenZero))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.SubjectKeyId", cert.SubjectKeyId))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.AuthorityKeyId", cert.AuthorityKeyId))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.OCSPServer", cert.OCSPServer))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.IssuingCertificateURL", cert.IssuingCertificateURL))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.DNSNames", cert.DNSNames))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.EmailAddresses", cert.EmailAddresses))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.IPAddresses", cert.IPAddresses))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.URIs", cert.URIs))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PermittedDNSDomainsCritical", cert.PermittedDNSDomainsCritical))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PermittedDNSDomains", cert.PermittedDNSDomains))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.ExcludedDNSDomains", cert.ExcludedDNSDomains))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PermittedIPRanges", cert.PermittedIPRanges))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.ExcludedIPRanges", cert.ExcludedIPRanges))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PermittedEmailAddresses", cert.PermittedEmailAddresses))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.ExcludedEmailAddresses", cert.ExcludedEmailAddresses))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PermittedURIDomains", cert.PermittedURIDomains))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.ExcludedURIDomains", cert.ExcludedURIDomains))
    
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.CRLDistributionPoints", cert.CRLDistributionPoints))
    
    fmt.Printf("%s", fmt.Sprintf("%30s: %v\n", "cert.PolicyIdentifiers", cert.PolicyIdentifiers))
    
    fmt.Printf("%s", fmt.Sprintf("%30s End of %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title))
    return
}