package service_function

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"

	// "crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"

	"strconv"

	"github.com/sirupsen/logrus"
	logger "github.com/vs-uulm/ztsfc_http_logger"
)

const (
	SFLOGGER_REGISTER_PACKETS_ONLY uint32 = 1 << iota
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
	name        string
	httpLogger  *logger.Logger
	logFileName string
	// logLevel    int
}

type HTTPMultipartFormFile struct {
	header  []*multipart.FileHeader
	content []byte
}

func NewServiceFunction() ServiceFunctionLogger {
	sf := new(ServiceFunctionLogger)
	sf.name = "logger"
	return *sf
}

func (sf *ServiceFunctionLogger) SetHttpLogFileName(_logFileName string) {
	sf.logFileName = _logFileName
}

func (sf *ServiceFunctionLogger) RunHttpLogger() error {
	var err error

	// Check if the log file name is set
	if sf.logFileName == "" {
		return errors.New("log file path is empty")
	}

	// Create a new log writer
	sf.httpLogger, err = logger.New(sf.logFileName, "info", "json", logger.Fields{"type": "http"})
	return err
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
		if u64 == 0 {
			logLevel = SFLOGGER_REGISTER_PACKETS_ONLY
		} else {
			//logLevel = uint32(u64)
			logLevel = uint32(u64)
		}
	} else {
		logLevel = SFLOGGER_REGISTER_PACKETS_ONLY
	}

	logLevel = SFLOGGER_PRINT_GENERAL_INFO | SFLOGGER_PRINT_HEADER_FIELDS | SFLOGGER_PRINT_BODY | SFLOGGER_PRINT_FORMS | SFLOGGER_PRINT_FORMS_FILE_CONTENT | SFLOGGER_PRINT_TLS_MAIN_INFO |
		SFLOGGER_PRINT_TLS_CERTIFICATES | SFLOGGER_PRINT_TLS_PUBLIC_KEY | SFLOGGER_PRINT_TLS_CERT_SIGNATURE

	//    fmt.Printf("log level: %d\n", logLevel)

	httpLogger := sf.httpLogger.WithFields(logrus.Fields{
		"Host":       req.Host,
		"URL":        req.URL,
		"RemoteAddr": req.RemoteAddr,
	})

	addr, ok := req.Header["X-Forwarded-For"]
	if ok && len(addr) > 0 {
		httpLogger = httpLogger.WithFields(logrus.Fields{"X-Forwarded-For": addr})
	}

	//
	// SFLOGGER_REGISTER_PACKETS_ONLY
	//

	if logLevel&SFLOGGER_REGISTER_PACKETS_ONLY != 0 {
		httpLogger.Info("HTTP request")
		forward = true
		return
	}

	// //
	// // SFLOGGER_PRINT_GENERAL_INFO
	// //

	if logLevel&SFLOGGER_PRINT_GENERAL_INFO != 0 {
		if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TransferEncoding": req.TransferEncoding})
		} else if len(req.TransferEncoding) > 0 {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TransferEncoding": req.TransferEncoding})
		}

		// if req.Cancel == nil {
		// 	if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
		// 		httpLogger = httpLogger.WithFields(logrus.Fields{"Cancel": "nil"})
		// 	}
		// } else {
		// 	httpLogger = httpLogger.WithFields(logrus.Fields{"Cancel": req.Cancel})
		// }

		httpLogger = httpLogger.WithFields(logrus.Fields{
			"Method":           req.Method,
			"Proto":            req.Proto,
			"Protocol Version": fmt.Sprintf("%d.%d", req.ProtoMajor, req.ProtoMinor),
			"ContentLength":    req.ContentLength,
			"Close":            req.Close,
		})
	}

	// //
	// // SFLOGGER_PRINT_HEADER_FIELDS
	// //

	if logLevel&SFLOGGER_PRINT_HEADER_FIELDS != 0 {
		httpLogger = httpLogger.WithFields(logrus.Fields{"Header": req.Header})
	}

	//
	// SFLOGGER_PRINT_BODY
	//

	if logLevel&SFLOGGER_PRINT_BODY != 0 {
		if req.Body == http.NoBody {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"Body": req.Body})
			}
		} else {
			// Manually save the request body
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				sf.httpLogger.Errorf("Request body reading error: %v", err)
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

	// //
	// // SFLOGGER_PRINT_FORMS
	// //

	if logLevel&SFLOGGER_PRINT_FORMS != 0 {

		// Manually save the request body
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			sf.httpLogger.Errorf("Request body reading error: %v", err)
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
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"Form": req2.Form})
			}
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"Form": req2.Form})
		}

		if len(req2.PostForm) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"PostForm": req2.PostForm})
			}
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"PostForm": req2.PostForm})
		}

		if req2.MultipartForm == nil {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm": req2.MultipartForm})
			}
		} else {
			if len(req2.MultipartForm.Value) == 0 {
				if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
					httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm Value": req2.MultipartForm.Value})
				}
			} else {
				httpLogger = httpLogger.WithFields(logrus.Fields{"MultipartForm Value": req2.MultipartForm.Value})
			}

			// operate received files
			if len(req2.MultipartForm.File) == 0 {
				if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
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

						if logLevel&SFLOGGER_PRINT_FORMS_FILE_CONTENT != 0 {
							file, err := pFH.Open()
							if err != nil {
								sf.httpLogger.Errorf("File %v opening error: %v", fName, err)
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
									sf.httpLogger.Errorf("File %v reading error: %v", fName, err)
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

	// //
	// // SFLOGGER_PRINT_TRAILERS
	// //

	if logLevel&SFLOGGER_PRINT_TRAILERS != 0 {
		if len(req.Trailer) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"Trailer": ""})
			}
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"Trailer": req.Trailer})
		}
	}

	// //
	// // SFLOGGER_PRINT_TLS_MAIN_INFO
	// //

	if logLevel&SFLOGGER_PRINT_TLS_MAIN_INFO != 0 {
		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.Version": getTLSVersionName(req.TLS.Version)})
		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.HandshakeComplete": req.TLS.HandshakeComplete})
		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.DidResume": req.TLS.DidResume})
		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.CipherSuite": tls.CipherSuiteName(req.TLS.CipherSuite)})

		if len(req.TLS.NegotiatedProtocol) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.NegotiatedProtocol": ""})
			}
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.NegotiatedProtocol": req.TLS.NegotiatedProtocol})
		}

		// httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.NegotiatedProtocol": req.TLS.NegotiatedProtocolIsMutual})
		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.ServerName": req.TLS.ServerName})

		if len(req.TLS.SignedCertificateTimestamps) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.SignedCertificateTimestamps": ""})
			}
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.SignedCertificateTimestamps": req.TLS.SignedCertificateTimestamps})
		}

		if len(req.TLS.OCSPResponse) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.OCSPResponse": ""})
			}
		} else {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.OCSPResponse": req.TLS.OCSPResponse})
		}

		// if len(req.TLS.TLSUnique) == 0 {
		// 	if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
		// 		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.TLSUnique": ""})
		// 	}
		// } else {
		// 	httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.TLSUnique": req.TLS.TLSUnique})
		// }
	}

	// //
	// // SFLOGGER_PRINT_TLS_CERTIFICATES
	// //

	if logLevel&SFLOGGER_PRINT_TLS_CERTIFICATES != 0 {
		httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.PeerCertificates": req.TLS.PeerCertificates})

		// for i := range req.TLS.PeerCertificates {
		// httpLogger = sf.addCertInfo(req.TLS.PeerCertificates[i], logLevel, httpLogger)
		// }

		if len(req.TLS.VerifiedChains) > 0 {
			httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.VerifiedChains": req.TLS.VerifiedChains})
			// for verifiedChainIndex := range req.TLS.VerifiedChains {
			// for certIndex := range req.TLS.VerifiedChains[verifiedChainIndex] {
			// httpLogger = sf.addCertInfo(req.TLS.VerifiedChains[verifiedChainIndex][certIndex], logLevel, httpLogger)
			// }
			// }
		} else {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				httpLogger = httpLogger.WithFields(logrus.Fields{"TLS.VerifiedChains": ""})
			}
		}
	}

	// //
	// // SFLOGGER_PRINT_REDIRECTED_RESPONSE
	// //

	if logLevel&SFLOGGER_PRINT_REDIRECTED_RESPONSE != 0 {
		if req.Response == nil {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
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

func (sf ServiceFunctionLogger) addCertInfo(cert *x509.Certificate, logLevel uint32, _logger *logrus.Entry) (logger *logrus.Entry) {
	logger = _logger
	//
	// SFLOGGER_PRINT_TLS_MAIN_INFO
	//

	if logLevel&SFLOGGER_PRINT_TLS_MAIN_INFO != 0 {
		logger = logger.WithFields(logrus.Fields{"cert.SignatureAlgorithm": cert.SignatureAlgorithm})
		logger = logger.WithFields(logrus.Fields{"cert.PublicKeyAlgorithm": cert.PublicKeyAlgorithm})
		logger = logger.WithFields(logrus.Fields{"cert.Version": cert.Version})
		logger = logger.WithFields(logrus.Fields{"cert.SerialNumber": cert.SerialNumber})
		logger = logger.WithFields(logrus.Fields{"cert.Issuer": cert.Issuer})
		logger = logger.WithFields(logrus.Fields{"cert.Subject": cert.Subject})
		logger = logger.WithFields(logrus.Fields{"cert.NotBefore": cert.NotBefore})
		logger = logger.WithFields(logrus.Fields{"cert.NotAfter": cert.NotAfter})
		logger = logger.WithFields(logrus.Fields{"cert.KeyUsage": cert.KeyUsage})

		if len(cert.Extensions) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.Extensions": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.Extensions": cert.Extensions})
			// for i := range cert.Extensions {
			// sf.httpLogger.Infof("%-32s:\n", fmt.Sprintf("cert.Extensions[%d]", i))
			// sf.printExtensionInfo(cert.Extensions[i], logLevel)
			// }
		}

		if len(cert.ExtraExtensions) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.ExtraExtensions": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.ExtraExtensions": cert.ExtraExtensions})
			// for i := range cert.ExtraExtensions {
			// sf.httpLogger.Infof("%-32s:\n", fmt.Sprintf("cert.ExtraExtensions[%d]", i))
			// sf.printExtensionInfo(cert.ExtraExtensions[i], logLevel)
			// }
		}

		if len(cert.UnhandledCriticalExtensions) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.UnhandledCriticalExtensions": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.UnhandledCriticalExtensions": cert.UnhandledCriticalExtensions})
		}

		if len(cert.ExtKeyUsage) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.ExtKeyUsage": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.ExtKeyUsage": cert.ExtKeyUsage})
		}

		if len(cert.UnknownExtKeyUsage) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.UnknownExtKeyUsage": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.UnknownExtKeyUsage": cert.UnknownExtKeyUsage})
		}

		logger = logger.WithFields(logrus.Fields{"cert.BasicConstraintsValid": cert.BasicConstraintsValid})
		logger = logger.WithFields(logrus.Fields{"cert.IsCA": cert.IsCA})
		logger = logger.WithFields(logrus.Fields{"cert.MaxPathLen": cert.MaxPathLen})
		logger = logger.WithFields(logrus.Fields{"cert.MaxPathLenZero": cert.MaxPathLenZero})

		if len(cert.SubjectKeyId) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.SubjectKeyId": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.SubjectKeyId": cert.SubjectKeyId})
		}

		if len(cert.AuthorityKeyId) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.AuthorityKeyId": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.AuthorityKeyId": cert.AuthorityKeyId})
		}

		if len(cert.OCSPServer) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.OCSPServer": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.OCSPServer": cert.OCSPServer})
			// sf.httpLogger.Infof("%-32s:\n", "cert.OCSPServers")
			// for i := range cert.OCSPServer {
			// sf.httpLogger.Infof("%-32s  - %v\n", "", cert.OCSPServer[i])
			// }
		}

		if len(cert.IssuingCertificateURL) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.IssuingCertificateURL": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.IssuingCertificateURL": cert.IssuingCertificateURL})
			// sf.httpLogger.Infof("%-32s:\n", "cert.OCSPServers")
			// for i := range cert.IssuingCertificateURL {
			// sf.httpLogger.Infof("%-32s  - %v\n", "", cert.IssuingCertificateURL[i])
			// }
		}

		if len(cert.DNSNames) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.DNSNames": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.DNSNames": cert.DNSNames})
			// sf.httpLogger.Infof("%-32s:\n", "cert.DNSNames")
			// for i := range cert.DNSNames {
			// sf.httpLogger.Infof("%-32s  - %v\n", "", cert.DNSNames[i])
			// }
		}

		if len(cert.EmailAddresses) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.EmailAddresses": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.EmailAddresses": cert.EmailAddresses})
			// sf.httpLogger.Infof("%-32s:\n", "cert.EmailAddresses")
			// for i := range cert.EmailAddresses {
			// sf.httpLogger.Infof("%-32s  - %v\n", "", cert.EmailAddresses[i])
			// }
		}

		if len(cert.IPAddresses) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.IPAddresses": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.IPAddresses": cert.IPAddresses})
			// sf.httpLogger.Infof("%-32s:\n", "cert.IPAddresses")
			// for i := range cert.IPAddresses {
			// sf.httpLogger.Infof("%-32s  - %v\n", "", cert.IPAddresses[i])
			// }
		}

		if len(cert.URIs) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.URIs": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.URIs": cert.URIs})
			// sf.httpLogger.Infof("%-32s:\n", "cert.URIs")
			// for i := range cert.URIs {
			// sf.httpLogger.Infof("%-32s  - %v\n", "", cert.URIs[i])
			// }
		}

		logger = logger.WithFields(logrus.Fields{"cert.PermittedDNSDomainsCritical": cert.PermittedDNSDomainsCritical})

		logger = logger.WithFields(logrus.Fields{"cert.PermittedDNSDomains": cert.PermittedDNSDomains})
		logger = logger.WithFields(logrus.Fields{"cert.ExcludedDNSDomains": cert.ExcludedDNSDomains})

		if len(cert.PermittedIPRanges) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.PermittedIPRanges": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.PermittedIPRanges": cert.PermittedIPRanges})
		}

		if len(cert.ExcludedIPRanges) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.ExcludedIPRanges": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.ExcludedIPRanges": cert.ExcludedIPRanges})
		}

		logger = logger.WithFields(logrus.Fields{"cert.PermittedEmailAddresses": cert.PermittedEmailAddresses})
		logger = logger.WithFields(logrus.Fields{"cert.ExcludedEmailAddresses": cert.ExcludedEmailAddresses})
		logger = logger.WithFields(logrus.Fields{"cert.PermittedURIDomains": cert.PermittedURIDomains})
		logger = logger.WithFields(logrus.Fields{"cert.ExcludedURIDomains": cert.ExcludedURIDomains})
		logger = logger.WithFields(logrus.Fields{"cert.CRLDistributionPoints": cert.CRLDistributionPoints})

		if len(cert.PolicyIdentifiers) == 0 {
			if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
				logger = logger.WithFields(logrus.Fields{"cert.PolicyIdentifiers": ""})
			}
		} else {
			logger = logger.WithFields(logrus.Fields{"cert.PolicyIdentifiers": cert.PolicyIdentifiers})
		}
	}

	//
	// SFLOGGER_PRINT_RAW
	//

	if logLevel&SFLOGGER_PRINT_RAW != 0 {
		logger = logger.WithFields(logrus.Fields{"cert.Raw": cert.Raw})
		logger = logger.WithFields(logrus.Fields{"cert.RawTBSCertificate": cert.RawTBSCertificate})

		if logLevel&SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0 {
			logger = logger.WithFields(logrus.Fields{"cert.RawSubjectPublicKeyInfo": cert.RawSubjectPublicKeyInfo})
		}

		logger = logger.WithFields(logrus.Fields{"cert.RawSubject": cert.RawSubject})
		logger = logger.WithFields(logrus.Fields{"cert.RawIssuer": cert.RawIssuer})

		if logLevel&SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0 {
			logger = logger.WithFields(logrus.Fields{"cert.Signature": cert.Signature})
		}
	}

	// //
	// // SFLOGGER_PRINT_TLS_CERT_SIGNATURE
	// //

	// if logLevel&SFLOGGER_PRINT_TLS_CERT_SIGNATURE != 0 {
	// sf.httpLogger.Infof("%-32s: %v\n", "cert.Signature", cert.Signature)
	// }

	// //
	// // SFLOGGER_PRINT_TLS_PUBLIC_KEY
	// //

	// if logLevel&SFLOGGER_PRINT_TLS_PUBLIC_KEY != 0 {
	// sf.httpLogger.Infof("%-32s: %v of type %T\n", "cert.PublicKey", cert.PublicKey, cert.PublicKey)
	// }

	// if logLevel&SFLOGGER_PRINT_TLS_MAIN_INFO != 0 {
	// sf.httpLogger.Infof("%-32s  End of %s\n", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%", title)
	// }
	return
}

// func (sf ServiceFunctionLogger) printExtensionInfo(ext pkix.Extension, logLevel uint32) {
// sf.httpLogger.Infof("%-32s  Id:          %v\n", "", ext.Id)
// sf.httpLogger.Infof("%-32s  Critical:    %v\n", "", ext.Critical)
// sf.httpLogger.Infof("%-32s  Value:       %s\n", "", string(ext.Value))
// sf.httpLogger.Infof("%-32s  Value (raw): %v\n", "", ext.Value)
// return
// }

// func (sf ServiceFunctionLogger) logSliceBytes(data []byte, name string, logLevel uint32) {
// if len(data) == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s: []\n", name)
// }
// } else {
// sf.httpLogger.Infof("%-32s:\n", name)
// for i := range data {
// sf.httpLogger.Infof("%-32s  - %v\n", "", data[i])
// }
// }
// }

// func (sf ServiceFunctionLogger) logSliceStrings(data []string, name string, logLevel uint32) {
// if len(data) == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s: []\n", name)
// }
// } else {
// sf.httpLogger.Infof("%-32s:\n", name)
// for i := range data {
// sf.httpLogger.Infof("%-32s  - %v\n", "", data[i])
// }
// }
// }

// func (sf ServiceFunctionLogger) logRaw(data []byte) {
// // Number of complete lines
// numLines := int(len(data) / 32)

// // Printf all lines as 16 + 16 hex symbols
// for i := 0; i < numLines-1; i++ {

// // Left indentation
// sf.httpLogger.Infof("%-32s  ", "")
// for j := 0; j < 16; j++ {
// sf.httpLogger.Infof("%02X ", data[i*32+j])
// }

// // Space between two columns
// sf.httpLogger.Infof("%s  ", "")
// for j := 0; j < 16; j++ {
// sf.httpLogger.Infof("%02X ", data[i*32+16+j])
// }

// // Next line at the end
// sf.httpLogger.Infof("\n")
// }

// // Last line has 1-31 symbol(s)
// // Left indentation
// sf.httpLogger.Infof("%-32s  ", "")

// // If the last symbol is in the first column
// if len(data)-numLines*32 <= 16 {
// for j := 0; j < len(data)-numLines*32; j++ {
// sf.httpLogger.Infof("%02X ", data[numLines*32+j])
// }
// // }
// } else {
// // If the last symbol is in the second column
// for j := 0; j < 16; j++ {
// sf.httpLogger.Infof("%02X ", data[numLines*32+j])
// }
// sf.httpLogger.Infof("%s  ", "")
// for j := 0; j < len(data)-numLines*32-16; j++ {
// sf.httpLogger.Infof("%02X ", data[numLines*32+16+j])
// }
// }

// // Next line at the end of the raw output
// sf.httpLogger.Infof("%s\n", "")
// }

// func (sf ServiceFunctionLogger) logCookie(c *http.Cookie, logLevel uint32) {
// sf.httpLogger.Infof("%-32s  - Name    : %v\n", "", c.Name)
// sf.httpLogger.Infof("%-32s    Value   : %v\n", "", c.Value)

// if len(c.Path) == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s    Path    : \"\"\n", "")
// }
// } else {
// sf.httpLogger.Infof("%-32s    Path    : %v\n", "", c.Path)
// }

// if len(c.Domain) == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s    Domain  : \"\"\n", "")
// }
// } else {
// sf.httpLogger.Infof("%-32s    Domain  : %v\n", "", c.Domain)
// }

// if c.Expires.IsZero() {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s    Expires : \"\"\n", "")
// }
// } else {
// sf.httpLogger.Infof("%-32s    Expires : %v\n", "", c.Expires)
// sf.httpLogger.Infof("%-32s      (raw) : %v\n", "", c.RawExpires)
// }

// if c.MaxAge == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s    MaxAge  : \"\"\n", "")
// }
// } else {
// sf.httpLogger.Infof("%-32s    MaxAge  : %v\n", "", c.MaxAge)
// }

// sf.httpLogger.Infof("%-32s    Secure  : %v\n", "", c.Secure)
// sf.httpLogger.Infof("%-32s    HttpOnly: %v\n", "", c.HttpOnly)
// sf.httpLogger.Infof("%-32s    SameSite: %v\n", "", getSamSiteModeInText(int(c.SameSite)))

// if len(c.Raw) == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s    Raw     : \"\"\n", "")
// }
// } else {
// sf.httpLogger.Infof("%-32s    Raw     : %v\n", "", c.Raw)
// }

// if len(c.Unparsed) == 0 {
// if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
// sf.httpLogger.Infof("%-32s    Raw     : []\n", "")
// }
// } else {
// for _, pair := range c.Unparsed {
// sf.httpLogger.Infof("%-32s              - %v\n", "", pair)
// }
// }
// }

// func getSamSiteModeInText(ss int) string {
// switch ss {
// case 0:
// return "SameSiteDefaultMode"
// case 1:
// return "SameSiteLaxMode"
// case 2:
// return "SameSiteStrictMode"
// case 3:
// return "SameSiteNoneMode"
// default:
// return "Unknown!"
// }
// }
