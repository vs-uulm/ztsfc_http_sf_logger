package service_function

import (
    "net/http"
    "fmt"
    // "time"
	"crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "bytes"
    "io/ioutil"
    "mime/multipart"
    "bufio"
    
    "strconv"
    
    "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
	"github.com/sirupsen/logrus"
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
	GetSFName() (name string)
}

type ServiceFunctionLogger struct {
    name string
    lw *logwriter.LogWriter
    logLevel int
	logFileName string
}

type HTTPMultipartFormFile struct {
	header	[]*multipart.FileHeader
	content	[]byte
}

func NewServiceFunction() ServiceFunctionLogger {
    sf := new(ServiceFunctionLogger)
    sf.name = "logger"
	return *sf
}

func (sf *ServiceFunctionLogger) SetHttpLogFileName (_logFileName string) {
	sf.logFileName = _logFileName 
}

func (sf *ServiceFunctionLogger) RunHttpLogger () {
	// Create a new log writer
    sf.lw = logwriter.New(sf.logFileName, "info", true)
}

func (sf ServiceFunctionLogger) GetSFName() string {
	return sf.name
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

	httpLogger := sf.lw.Logger.WithFields(logrus.Fields{
		"Host": req.Host,
		"URL": req.URL,
		"RemoteAddr": req.RemoteAddr,
	})
	
	addr, ok := req.Header["X-Forwarded-For"]
	if ok && len(addr) > 0 {
		httpLogger = httpLogger.WithFields(logrus.Fields{"X-Forwarded-For": addr})
	}
		
    //
    // SFLOGGER_REGISTER_PACKETS_ONLY
    //

    if (logLevel & SFLOGGER_REGISTER_PACKETS_ONLY != 0) {
		httpLogger.Info("HTTP request")
        forward = true
        return
    }

    //
    // SFLOGGER_PRINT_GENERAL_INFO
    //

    if (logLevel & SFLOGGER_PRINT_GENERAL_INFO != 0) {
		if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TransferEncoding": req.TransferEncoding})
        } else if (len(req.TransferEncoding) > 0) {
            httpLogger = httpLogger.WithFields(logrus.Fields{"TransferEncoding": req.TransferEncoding})
        }
		
		
		if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) && (req.Cancel == nil) {
			httpLogger = httpLogger.WithFields(logrus.Fields{"Cancel": "nil"})
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"Cancel": req.Cancel})
		}
		
		httpLogger = httpLogger.WithFields(logrus.Fields{
			"Method": req.Method,
			"Proto": req.Proto,
			"Protocol Version": fmt.Sprintf("%d.%d", req.ProtoMajor, req.ProtoMinor),
			"ContentLength": req.ContentLength,
			"Close": req.Close,
			})
    }

    //
    // SFLOGGER_PRINT_HEADER_FIELDS
    //

    if (logLevel & SFLOGGER_PRINT_HEADER_FIELDS != 0) {
		httpLogger = httpLogger.WithFields(logrus.Fields{"Header": req.Header})
    }

    //
    // SFLOGGER_PRINT_BODY
    //

    if (logLevel & SFLOGGER_PRINT_BODY != 0) {
        if req.Body == http.NoBody {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
				httpLogger = httpLogger.WithFields(logrus.Fields{"Body": req.Body})
            }
        } else {
            // Manually save the request body
            body, err := ioutil.ReadAll(req.Body)
            if err != nil {
                sf.lw.Logger.Errorf("Request body reading error: %v", err)
				forward = false
                return
            }

            req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

            // create a new request for parsing the body
            req2, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
            req2.Header = req.Header
			
			httpLogger = httpLogger.WithFields(logrus.Fields{"Body": string(body)})
        }

        // if req.GetBody == nil {
            // if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                // httpLogger.Infof("%-32s: <nil>\n", "GetBody")
            // }
        // } else {
            // // ToDo: print GetBody
            // httpLogger.Infof("%-32s: present (%v)\n", "GetBody", req.GetBody)
        // }
    }

    //
    // SFLOGGER_PRINT_FORMS
    //

    if (logLevel & SFLOGGER_PRINT_FORMS != 0) {

        // Manually save the request body
        body, err := ioutil.ReadAll(req.Body)
        if err != nil {
            sf.lw.Logger.Errorf("Request body reading error: %v", err)
			forward = false
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
				httpLogger = httpLogger.WithFields(logrus.Fields{"Form": req2.Form})
            }
        } else {
            httpLogger = httpLogger.WithFields(logrus.Fields{"Form": req2.Form})
        }
        

        if len(req2.PostForm) == 0 {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger = httpLogger.WithFields(logrus.Fields{"PostForm": req2.PostForm})
            }
        } else {
            httpLogger = httpLogger.WithFields(logrus.Fields{"PostForm": req2.PostForm})
        }

        if (req2.MultipartForm == nil) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm": req2.MultipartForm})
            }
        } else {
            if len(req2.MultipartForm.Value) == 0 {
                if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
					httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm Value": req2.MultipartForm.Value})
                }
            } else {
                httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm Value": req2.MultipartForm.Value})
            }


			// operate received files
            if len(req2.MultipartForm.File) == 0 {
                if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                    httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm File": req2.MultipartForm.File})
                }
            } else {
				mfFiles := make(map[string]HTTPMultipartFormFile)
				var mfFile HTTPMultipartFormFile
				
				// type Form struct {
				// 		Value map[string][]string
				//  	File  map[string][]*FileHeader
				// }
				for fName, fHeaders := range req2.MultipartForm.File {

					// //
					// // SFLOGGER_PRINT_FORMS_FILE_CONTENT
					// //

					mfFile.header = fHeaders
					
					// var fh multipart.FileHeader
					
					// type FileHeader struct {
					// 		Filename string
					// 		Header   textproto.MIMEHeader
					// 		Size     int64 // Go 1.9
					// }

					fmt.Printf("req2.MultipartForm.File = %+v\n", req2.MultipartForm.File)

                    for iFH, pFH := range fHeaders {
						
						fmt.Printf("fh[%d].Filename: %v\n", iFH, pFH.Filename)
						fmt.Printf("fh[%d].Size: %v\n", iFH, pFH.Size)

						// type MIMEHeader map[string][]string
						for mimeHeaderName, mimeHeaders := range pFH.Header {
							fmt.Printf("%v\n", mimeHeaderName)
							for _, mimeHeader := range mimeHeaders {
								fmt.Printf("\t%v\n", mimeHeader)
							}
						}

						if (logLevel & SFLOGGER_PRINT_FORMS_FILE_CONTENT != 0) {
							file, err := pFH.Open()
							if err != nil {
								sf.lw.Logger.Errorf("File %v opening error: %v", fName, err)
								forward = false
								return
							} else {
								fmt.Printf("    File %v content:\n", fName)
								defer file.Close()

								scanner := bufio.NewScanner(file)
								for scanner.Scan() {
									mfFile.content = append(mfFile.content, scanner.Text()...)
								}

								if err := scanner.Err(); err != nil {
									sf.lw.Logger.Errorf("File %v reading error: %v", fName, err)
									forward = false
									return
								}
							}
						}
					}
					mfFiles[fName] = mfFile
					fmt.Printf("mfFiles = %v\n", mfFiles)
                }
				fmt.Printf("+++mfFiles = %v\n", mfFiles)
				httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm File": mfFiles})
				httpLogger.Info("OK")
            }
        }
    }
    
    //
    // SFLOGGER_PRINT_TRAILERS
    //

    if (logLevel & SFLOGGER_PRINT_TRAILERS != 0) {    
        if (len(req.Trailer) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger.Infof("%-32s: map[]\n", "Trailer")
            }
        } else {
            httpLogger.Infof("%-32s: %v\n", "Trailer", req.Trailer)
        }
    }


    //
    // SFLOGGER_PRINT_TLS_MAIN_INFO
    //

    if (logLevel & SFLOGGER_PRINT_TLS_MAIN_INFO != 0) {
        if (req.TLS.Version >=769) && (req.TLS.Version <= 772) {
            httpLogger.Infof("%-32s: 1.%d\n", "TLS.Version", req.TLS.Version-769)
        } else {
            httpLogger.Infof("%-32s: %v\n", "TLS.Version", "WRONG VALUE!")
        }
        httpLogger.Infof("%-32s: %v\n", "TLS.HandshakeComplete", req.TLS.HandshakeComplete)
        
        httpLogger.Infof("%-32s: %v\n", "TLS.DidResume", req.TLS.DidResume)
        
        httpLogger.Infof("%-32s: %v\n", "TLS.CipherSuite", tls.CipherSuiteName(req.TLS.CipherSuite))
        
        if (len(req.TLS.NegotiatedProtocol) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger.Infof("%-32s: \"\"\n", "req.TLS.NegotiatedProtocol")
            }
        } else {
            httpLogger.Infof("%-32s: %v\n", "TLS.NegotiatedProtocol", req.TLS.NegotiatedProtocol)
        }        
        
        httpLogger.Infof("%-32s: %v\n", "TLS.NegotiatedProtocolIsMutual", req.TLS.NegotiatedProtocolIsMutual)
        
        httpLogger.Infof("%-32s: %v\n", "TLS.ServerName", req.TLS.ServerName)
        
        
        
        if (len(req.TLS.SignedCertificateTimestamps) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger.Infof("%-32s: []\n", "TLS.SignedCertificateTimestamps")
            }            
        } else {
            httpLogger.Infof("%-32s:\n", "TLS.SignedCertificateTimestamps")
            for _, s := range req.TLS.SignedCertificateTimestamps {
                httpLogger.Infof("%-32s  - %v\n", "", s)
            }
        }

        
        if (len(req.TLS.OCSPResponse) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger.Infof("%-32s: []\n", "TLS.OCSPResponse")
            }            
        } else {
            httpLogger.Infof("%-32s: %v\n", "TLS.OCSPResponse", req.TLS.OCSPResponse)
        }
        
        if (len(req.TLS.TLSUnique) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger.Infof("%-32s: []\n", "TLS.TLSUnique")
            }            
        } else {
            httpLogger.Infof("%-32s: %v\n", "TLS.TLSUnique", req.TLS.TLSUnique)
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
            httpLogger.Infof("%-32s  TLS.VerifiedChains: []\n", "")
        } 
    }

    //
    // SFLOGGER_PRINT_REDIRECTED_RESPONSE
    //

    if (logLevel & SFLOGGER_PRINT_REDIRECTED_RESPONSE != 0) {
        if (req.Response == nil) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                httpLogger.Infof("%-32s: <nil>\n", "TLS.Response")
            }
        } else {
            // ToDo: print Response
            httpLogger.Infof("%-32s: %v\n", "Response", req.Response)
        }
    }

	httpLogger.Info("HTTP request")
    forward = true
    return
}

func (sf ServiceFunctionLogger) printCertInfo(cert *x509.Certificate, title string, logLevel uint32) {
    

    //
    // SFLOGGER_PRINT_TLS_MAIN_INFO
    //

    if (logLevel & SFLOGGER_PRINT_TLS_MAIN_INFO != 0) {
        sf.lw.Logger.Infof("%-32s  %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.SignatureAlgorithm", cert.SignatureAlgorithm)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.PublicKeyAlgorithm", cert.PublicKeyAlgorithm)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.Version", cert.Version)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.SerialNumber", cert.SerialNumber)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.Issuer", cert.Issuer)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.Subject", cert.Subject)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.NotBefore", cert.NotBefore)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.NotAfter", cert.NotAfter)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.KeyUsage", cert.KeyUsage)
        
        if (len(cert.Extensions) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.Extensions")
            }
        } else {
            for i := range cert.Extensions {
                sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.Extensions[%d]",i))
                sf.printExtensionInfo(cert.Extensions[i], logLevel)
            }
        }
        
        
        if (len(cert.ExtraExtensions) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.ExtraExtensions")
            }
        } else {
            for i := range cert.ExtraExtensions {
                sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.ExtraExtensions[%d]",i))
                sf.printExtensionInfo(cert.ExtraExtensions[i], logLevel)
            }
        }
        
        
        if (len(cert.UnhandledCriticalExtensions) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.UnhandledCriticalExtensions")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "UnhandledCriticalExtensions", cert.UnhandledCriticalExtensions)
        }
        
        
        if (len(cert.ExtKeyUsage) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.ExtKeyUsage")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "ExtKeyUsage", cert.ExtKeyUsage)
        }
        
        
        if (len(cert.UnknownExtKeyUsage) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.UnknownExtKeyUsage")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "cert.UnknownExtKeyUsage", cert.UnknownExtKeyUsage)
        }
        
       
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.BasicConstraintsValid", cert.BasicConstraintsValid)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.IsCA", cert.IsCA)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.MaxPathLen", cert.MaxPathLen)
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.MaxPathLenZero", cert.MaxPathLenZero)
        
        if (len(cert.SubjectKeyId) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.SubjectKeyId")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "cert.SubjectKeyId", cert.SubjectKeyId)
        }
        
        
        if (len(cert.AuthorityKeyId) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.AuthorityKeyId")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "cert.AuthorityKeyId", cert.AuthorityKeyId)
        }
        
        
        if (len(cert.OCSPServer) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.OCSPServer")
            }
        } else {
            sf.lw.Logger.Infof("%-32s:\n", "cert.OCSPServers")
            for i := range cert.OCSPServer {
                sf.lw.Logger.Infof("%-32s  - %v\n", "", cert.OCSPServer[i])
            }
        }
        
        if (len(cert.IssuingCertificateURL) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.IssuingCertificateURL")
            }
        } else {
            sf.lw.Logger.Infof("%-32s:\n", "cert.OCSPServers")
            for i := range cert.IssuingCertificateURL {
                sf.lw.Logger.Infof("%-32s  - %v\n", "", cert.IssuingCertificateURL[i])
            }
        }
        
        
        if (len(cert.DNSNames) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.DNSNames")
            }
        } else {
            sf.lw.Logger.Infof("%-32s:\n", "cert.DNSNames")
            for i := range cert.DNSNames {
                sf.lw.Logger.Infof("%-32s  - %v\n", "", cert.DNSNames[i])
            }
        }
        
        if (len(cert.EmailAddresses) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.EmailAddresses")
            }
        } else {
            sf.lw.Logger.Infof("%-32s:\n", "cert.EmailAddresses")
            for i := range cert.EmailAddresses {
                sf.lw.Logger.Infof("%-32s  - %v\n", "", cert.EmailAddresses[i])
            }
        }
        
        
        if (len(cert.IPAddresses) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.IPAddresses")
            }
        } else {
            sf.lw.Logger.Infof("%-32s:\n", "cert.IPAddresses")
            for i := range cert.IPAddresses {
                sf.lw.Logger.Infof("%-32s  - %v\n", "", cert.IPAddresses[i])
            }
        }
        
        if (len(cert.URIs) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.URIs")
            }
        } else {
            sf.lw.Logger.Infof("%-32s:\n", "cert.URIs")
            for i := range cert.URIs {
                sf.lw.Logger.Infof("%-32s  - %v\n", "", cert.URIs[i])
            }
        }

        sf.lw.Logger.Infof("%-32s: %v\n", "cert.PermittedDNSDomainsCritical", cert.PermittedDNSDomainsCritical)
        
        sf.logSliceStrings(cert.PermittedDNSDomains, "cert.PermittedDNSDomains", logLevel)
        
        sf.logSliceStrings(cert.ExcludedDNSDomains, "cert.ExcludedDNSDomains", logLevel)
        
        if (len(cert.PermittedIPRanges) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.PermittedIPRanges")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "cert.PermittedIPRanges", cert.PermittedIPRanges)
        }
        
        
        if (len(cert.ExcludedIPRanges) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.ExcludedIPRanges")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "cert.ExcludedIPRanges", cert.ExcludedIPRanges)
        }
       

        sf.logSliceStrings(cert.PermittedEmailAddresses, "cert.PermittedEmailAddresses", logLevel)
        
        sf.logSliceStrings(cert.ExcludedEmailAddresses, "cert.ExcludedEmailAddresses", logLevel)
        
        sf.logSliceStrings(cert.PermittedURIDomains, "cert.PermittedURIDomains", logLevel)
        
        sf.logSliceStrings(cert.ExcludedURIDomains, "cert.ExcludedURIDomains", logLevel)
        
        
        sf.logSliceStrings(cert.CRLDistributionPoints, "cert.CRLDistributionPoints", logLevel)
        
        if (len(cert.PolicyIdentifiers) == 0) {
            if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
                sf.lw.Logger.Infof("%-32s: []\n", "cert.PolicyIdentifiers")
            }
        } else {
            sf.lw.Logger.Infof("%-32s: %v\n", "cert.PolicyIdentifiers", cert.PolicyIdentifiers)
        }
    }
    
    //
    // SFLOGGER_PRINT_RAW
    //

    if (logLevel & SFLOGGER_PRINT_RAW != 0) {
        sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.Raw"))
        sf.logRaw(cert.Raw)      
        
        sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.RawTBSCertificate"))
        sf.logRaw(cert.RawTBSCertificate)
        
        if (logLevel & SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0) {
            sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.RawSubjectPublicKeyInfo"))
            sf.logRaw(cert.RawSubjectPublicKeyInfo)
        }
        
        sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.RawSubject"))
        sf.logRaw(cert.RawSubject)
        
        sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.RawIssuer"))
        sf.logRaw(cert.RawIssuer)
        
        if (logLevel & SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0) {
            sf.lw.Logger.Infof("%-32s:\n", fmt.Sprintf("cert.Signature (raw)"))
            sf.logRaw(cert.Signature)
        }
    }
    
    //
    // SFLOGGER_PRINT_TLS_CERT_SIGNATURE
    //

    if (logLevel & SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0) {
        sf.lw.Logger.Infof("%-32s: %v\n", "cert.Signature", cert.Signature)
    }
    
    
    //
    // SFLOGGER_PRINT_TLS_PUBLIC_KEY
    //

    if (logLevel & SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0) {
        sf.lw.Logger.Infof("%-32s: %v of type %T\n", "cert.PublicKey", cert.PublicKey, cert.PublicKey)
    }
    
    if (logLevel & SFLOGGER_PRINT_TLS_MAIN_INFO != 0) {
        sf.lw.Logger.Infof("%-32s  End of %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title)
    }
    return
}

func (sf ServiceFunctionLogger) printExtensionInfo(ext pkix.Extension, logLevel uint32) {
    sf.lw.Logger.Infof("%-32s  Id:          %v\n", "", ext.Id)
    sf.lw.Logger.Infof("%-32s  Critical:    %v\n", "", ext.Critical)
    sf.lw.Logger.Infof("%-32s  Value:       %s\n", "", string(ext.Value))
    sf.lw.Logger.Infof("%-32s  Value (raw): %v\n", "", ext.Value)
    return
}


func (sf ServiceFunctionLogger) logSliceBytes(data []byte, name string, logLevel uint32) {
    if (len(data) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s: []\n", name)
        }
    } else {
        sf.lw.Logger.Infof("%-32s:\n", name)
        for i := range data {
            sf.lw.Logger.Infof("%-32s  - %v\n", "", data[i])
        }
    }
}

func (sf ServiceFunctionLogger) logSliceStrings(data []string, name string, logLevel uint32) {
    if (len(data) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s: []\n", name)
        }
    } else {                                                                                                                                                                                                                                                                                                                                                  
        sf.lw.Logger.Infof("%-32s:\n", name)
        for i := range data {
            sf.lw.Logger.Infof("%-32s  - %v\n", "", data[i])
        }
    }
}

func (sf ServiceFunctionLogger) logRaw(data []byte) {
    // Number of complete lines
    numLines := int(len(data) / 32)
    
    // Printf all lines as 16 + 16 hex symbols
    for i := 0; i < numLines-1; i++ {
        
        // Left indentation
        sf.lw.Logger.Infof("%-32s  ", "")
        for j := 0; j < 16; j++ {
            sf.lw.Logger.Infof("%02X ", data[i * 32 + j])
        }
        
        // Space between two columns
        sf.lw.Logger.Infof("%s  ", "")
        for j := 0; j < 16; j++ {
            sf.lw.Logger.Infof("%02X ", data[i * 32 + 16 + j])
        }
        
        // Next line at the end
        sf.lw.Logger.Infof("\n")
    }
    
    // Last line has 1-31 symbol(s)
    // Left indentation
    sf.lw.Logger.Infof("%-32s  ", "")

    // If the last symbol is in the first column
    if (len(data) - numLines * 32 <= 16) {
        for j := 0; j < len(data) - numLines * 32; j++ {
            sf.lw.Logger.Infof("%02X ", data[numLines * 32 + j])
        }
    // }
    } else {
    // If the last symbol is in the second column
        for j := 0; j < 16; j++ {
            sf.lw.Logger.Infof("%02X ", data[numLines * 32 + j])
        }
        sf.lw.Logger.Infof("%s  ", "")
        for j := 0; j < len(data) - numLines * 32 - 16; j++ {
            sf.lw.Logger.Infof("%02X ", data[numLines * 32 + 16 + j])
        }
    }
    
    // Next line at the end of the raw output
    sf.lw.Logger.Infof("%s\n", "")
}

func (sf ServiceFunctionLogger) logCookie(c *http.Cookie, logLevel uint32) {
    sf.lw.Logger.Infof("%-32s  - Name    : %v\n", "", c.Name)
    sf.lw.Logger.Infof("%-32s    Value   : %v\n", "", c.Value)
    
    if (len(c.Path) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s    Path    : \"\"\n", "")
        }
    } else {
        sf.lw.Logger.Infof("%-32s    Path    : %v\n", "", c.Path)
    }
    
    if (len(c.Domain) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s    Domain  : \"\"\n", "")
        }
    } else {
        sf.lw.Logger.Infof("%-32s    Domain  : %v\n", "", c.Domain)
    }
    
    if c.Expires.IsZero() {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s    Expires : \"\"\n", "")
        }
    } else {
        sf.lw.Logger.Infof("%-32s    Expires : %v\n", "", c.Expires)
        sf.lw.Logger.Infof("%-32s      (raw) : %v\n", "", c.RawExpires)
    }
    
    if (c.MaxAge == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s    MaxAge  : \"\"\n", "")
        }
    } else {
        sf.lw.Logger.Infof("%-32s    MaxAge  : %v\n", "", c.MaxAge)
    }
    
    sf.lw.Logger.Infof("%-32s    Secure  : %v\n", "", c.Secure)
    sf.lw.Logger.Infof("%-32s    HttpOnly: %v\n", "", c.HttpOnly)
    sf.lw.Logger.Infof("%-32s    SameSite: %v\n", "", getSamSiteModeInText(int(c.SameSite)))
    
    if (len(c.Raw) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s    Raw     : \"\"\n", "")
        }
    } else {
        sf.lw.Logger.Infof("%-32s    Raw     : %v\n", "", c.Raw)
    }
    
    if (len(c.Unparsed) == 0) {
        if (logLevel & SFLOGGER_PRINT_EMPTY_FIELDS != 0) {
            sf.lw.Logger.Infof("%-32s    Raw     : []\n", "")
        }
    } else {
        for _, pair := range c.Unparsed {
            sf.lw.Logger.Infof("%-32s              - %v\n", "", pair)
        }
    }
}

func getSamSiteModeInText(ss int) string {
    switch ss {
        case 0: return "SameSiteDefaultMode"
        case 1: return "SameSiteLaxMode"
        case 2: return "SameSiteStrictMode"
        case 3: return "SameSiteNoneMode"
        default: return "Unknown!"
    }
}