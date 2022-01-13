package httplogger

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strconv"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/config"
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

type HTTPMultipartFormFile struct {
	fileHeadersPointers []*multipart.FileHeader
	content             []byte
}

type HTTPLogger struct {
	packetLogger *logger.Logger
	fields       logger.Fields
}

// New() creates a new instance of the HTTP Logger
func New() (*HTTPLogger, error) {
	// Create an instance of the http packets logger
	packetLogger, err := logger.New(config.Config.SF.LogFilePath,
		"info",
		"json",
		logger.Fields{"type": "http"},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create an http logger instance: %s", err.Error())
	}

	return &HTTPLogger{packetLogger: packetLogger}, nil
}

func (httpl *HTTPLogger) ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool) {
	var (
		logLevel         uint32 = SFLOGGER_REGISTER_PACKETS_ONLY
		LoggerHeaderName string = "Sfloggerlevel"
	)

	// Get a logging level value from an HTTP request packet header
	logLevelString, ok := req.Header[LoggerHeaderName]
	if !ok {
		httpl.packetLogger.WithFields(httpl.fields).Error("the logging level header is absent")

		io.WriteString(w, "A packet logging level is not set. Attention! The connection could be compromised.")
		w.WriteHeader(http.StatusForbidden) // 403
		return
	}
	req.Header.Del(LoggerHeaderName)

	// Convert the string into uint32 value
	u64, err := strconv.ParseUint(logLevelString[0], 10, 32)
	if err != nil {
		httpl.packetLogger.WithFields(httpl.fields).Errorf("unable to parse the logginbg level value '%s'", logLevelString[0])
		return false
	}
	logLevel = uint32(u64)

	// SFLOGGER_REGISTER_PACKETS_ONLY
	// SFLOGGER_PRINT_GENERAL_INFO
	// SFLOGGER_PRINT_HEADER_FIELDS
	// SFLOGGER_PRINT_TRAILERS
	// SFLOGGER_PRINT_BODY
	// SFLOGGER_PRINT_FORMS
	// SFLOGGER_PRINT_FORMS_FILE_CONTENT
	// SFLOGGER_PRINT_TLS_MAIN_INFO
	// SFLOGGER_PRINT_TLS_CERTIFICATES
	// SFLOGGER_PRINT_TLS_PUBLIC_KEY
	// SFLOGGER_PRINT_TLS_CERT_SIGNATURE
	// SFLOGGER_PRINT_RAW
	// SFLOGGER_PRINT_REDIRECTED_RESPONSE
	// SFLOGGER_PRINT_EMPTY_FIELDS

	// DEBUG

	logLevel =
		// SFLOGGER_PRINT_GENERAL_INFO |
		// SFLOGGER_PRINT_HEADER_FIELDS |
		// SFLOGGER_PRINT_TRAILERS |
		// SFLOGGER_PRINT_BODY |
		// SFLOGGER_PRINT_FORMS |
		// SFLOGGER_PRINT_FORMS_FILE_CONTENT |
		// SFLOGGER_PRINT_TLS_MAIN_INFO |
		SFLOGGER_PRINT_TLS_CERTIFICATES

	// END DEBUG

	httpl.fields = logger.Fields{
		"Host":       req.Host,
		"URL":        req.URL,
		"RemoteAddr": req.RemoteAddr,
	}

	addr, ok := req.Header["X-Forwarded-For"]
	if ok && len(addr) > 0 {
		httpl.fields["X-Forwarded-For"] = addr
	}

	// SFLOGGER_REGISTER_PACKETS_ONLY
	if logLevel&SFLOGGER_REGISTER_PACKETS_ONLY != 0 {
		httpl.packetLogger.WithFields(httpl.fields).Info("HTTP request")
		forward = true
		return
	}

	// SFLOGGER_PRINT_GENERAL_INFO
	if logLevel&SFLOGGER_PRINT_GENERAL_INFO != 0 {
		httpl.addGeneralInfo(req, logLevel)
	}

	// SFLOGGER_PRINT_HEADER_FIELDS
	if logLevel&SFLOGGER_PRINT_HEADER_FIELDS != 0 {
		httpl.addHeaderFields(req, logLevel)
	}

	// SFLOGGER_PRINT_TRAILERS
	if logLevel&SFLOGGER_PRINT_TRAILERS != 0 {
		httpl.addTrailersInfo(req, logLevel)
	}

	// SFLOGGER_PRINT_BODY
	if logLevel&SFLOGGER_PRINT_BODY != 0 {
		err = httpl.addBodyFields(req, logLevel)
		if err != nil {
			return false
		}
	}

	// SFLOGGER_PRINT_FORMS
	if logLevel&(SFLOGGER_PRINT_FORMS|SFLOGGER_PRINT_FORMS_FILE_CONTENT) != 0 {
		err = httpl.addFormsFields(req, logLevel)
		if err != nil {
			return false
		}
	}

	// SFLOGGER_PRINT_TLS_MAIN_INFO
	if logLevel&SFLOGGER_PRINT_TLS_MAIN_INFO != 0 {
		httpl.addTLSMainInfo(req, logLevel)
	}

	// SFLOGGER_PRINT_TLS_CERTIFICATES
	if logLevel&SFLOGGER_PRINT_TLS_CERTIFICATES != 0 {
		httpl.addTLSCertInfo(req, logLevel)
	}

	// SFLOGGER_PRINT_REDIRECTED_RESPONSE
	if logLevel&SFLOGGER_PRINT_REDIRECTED_RESPONSE != 0 {
		httpl.addPredictedResponce(req, logLevel)
	}

	httpl.packetLogger.WithFields(httpl.fields).Info("HTTP request")
	forward = true
	return
}

func (httpl *HTTPLogger) GetSFName() string {
	return "HTTP Logger"
}

// GetTLSVersionName converts uint16 value of http request TLS.Version field into a TSL version name
func getTLSVersionName(input uint16) string {
	switch input {
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
	default:
		return "unknown"
	}
}

func (httpl *HTTPLogger) addGeneralInfo(req *http.Request, logLevel uint32) {
	httpl.fields["TransferEncoding"] = req.TransferEncoding
	httpl.fields["Method"] = req.Method
	httpl.fields["Proto"] = req.Proto
	httpl.fields["Protocol Version"] = fmt.Sprintf("%d.%d", req.ProtoMajor, req.ProtoMinor)
	httpl.fields["ContentLength"] = req.ContentLength
	httpl.fields["Close"] = req.Close
}

func (httpl *HTTPLogger) addHeaderFields(req *http.Request, logLevel uint32) {
	httpl.fields["Header"] = req.Header

	xff_req, ok := req.Header["X-Forwarded-For"]
	if ok && len(xff_req) > 0 {
		httpl.deleteFieldIfPresent("X-Forwarded-For")
	}
}

func (httpl *HTTPLogger) addTrailersInfo(req *http.Request, logLevel uint32) {
	// if len(req.Trailer) == 0 {
	// 	if logLevel&SFLOGGER_PRINT_EMPTY_FIELDS != 0 {
	// 		httpLogger = httpLogger.WithFields(logrus.Fields{"Trailer": ""})
	// 	}
	// } else {
	// 	httpLogger = httpLogger.WithFields(logrus.Fields{"Trailer": req.Trailer})
	// }

	httpl.fields["Trailer"] = req.Trailer
}

func (httpl *HTTPLogger) addBodyFields(req *http.Request, logLevel uint32) error {
	if req.Body == http.NoBody {
		httpl.fields["Body"] = req.Body
	} else {
		// ! ToDo: debug a request body printing!
		// Manually save the request body
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("httplogger: addBodyFields(): unable to read the request body: %w", err)
		}

		// req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		// !ToDo: check if creating a copy of an incoming request is necessary

		// // Create a new request for parsing the body
		// req2, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
		// if err != nil {
		// 	return false, fmt.Errorf("httplogger: addBodyFields(): unable to create a copy of the request: %w", err)
		// }
		// req2.Header = req.Header

		httpl.fields["Body"] = string(body)
	}
	return nil
}

func (httpl *HTTPLogger) addFormsFields(req *http.Request, logLevel uint32) error {
	// Manually save the request body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("httplogger: addFormsFields(): unable to read the request body: %w", err)
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	// Create a copy of the request for parsing the body
	req2, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("httplogger: addFormsFields(): unable to create a copy of the request: %w", err)
	}
	req2.Header = req.Header

	// Allocate 32,5 MB for parsing the req2uest MultipartForm
	// ParseMultipartForm() includes a call of ParseForm()
	req2.ParseMultipartForm(32<<20 + 512)

	httpl.fields["Form"] = req2.Form
	httpl.fields["PostForm"] = req2.PostForm

	// Check if an instance of the multipart.Form struct has been created
	if req2.MultipartForm == nil {
		httpl.fields["MultipartForm"] = req2.MultipartForm
	} else {
		// Output MultipartForm Values
		httpl.fields["MultipartForm Value"] = req2.MultipartForm.Value

		// Output received files information
		if req2.MultipartForm.File == nil {
			httpl.fields["MultipartForm File"] = req2.MultipartForm.File
		} else {
			mfFiles := make(map[string]HTTPMultipartFormFile)
			var mfFile HTTPMultipartFormFile

			for fieldName, fileHeadersPointers := range req2.MultipartForm.File {
				mfFile.fileHeadersPointers = fileHeadersPointers

				// INFO:
				// type FileHeader struct {
				// 		Filename string
				// 		Header   textproto.MIMEHeader
				// 		Size     int64 // Go 1.9
				// }

				for iFH, pFH := range fileHeadersPointers {

					fmt.Printf("fh[%d].Filename: %v\n", iFH, pFH.Filename)
					fmt.Printf("fh[%d].Size: %v\n", iFH, pFH.Size)

					// INFO:
					// type textproto.MIMEHeader map[string][]string

					for mimeHeaderName, mimeHeaders := range pFH.Header {
						fmt.Printf("%v\n", mimeHeaderName)
						for _, mimeHeader := range mimeHeaders {
							fmt.Printf("\t%v\n", mimeHeader)
						}
					}

					// SFLOGGER_PRINT_FORMS_FILE_CONTENT
					if logLevel&SFLOGGER_PRINT_FORMS_FILE_CONTENT != 0 {
						f, err := pFH.Open()
						if err != nil {
							return fmt.Errorf("httplogger: addFormsFields(): unable to open a file '%s': %w", fieldName, err)
						}
						defer f.Close()

						fmt.Printf("    File %s content:\n", fieldName)
						scanner := bufio.NewScanner(f)
						for scanner.Scan() {
							mfFile.content = append(mfFile.content, scanner.Text()...)
						}

						if err := scanner.Err(); err != nil {
							return fmt.Errorf("httplogger: addFormsFields(): unable to read a file '%s': %w", fieldName, err)
						}
					}
				}
				mfFiles[fieldName] = mfFile
			}
			httpl.fields["MultipartForm File"] = mfFiles
		}
	}
	return nil
}

func (httpl *HTTPLogger) addTLSMainInfo(req *http.Request, logLevel uint32) {
	httpl.fields["TLS.Version"] = getTLSVersionName(req.TLS.Version)
	httpl.fields["TLS.HandshakeComplete"] = req.TLS.HandshakeComplete
	httpl.fields["TLS.DidResume"] = req.TLS.DidResume
	httpl.fields["TLS.CipherSuite"] = tls.CipherSuiteName(req.TLS.CipherSuite)
	httpl.fields["TLS.NegotiatedProtocol"] = req.TLS.NegotiatedProtocol
	httpl.fields["TLS.ServerName"] = req.TLS.ServerName
	httpl.fields["TLS.SignedCertificateTimestamps"] = req.TLS.SignedCertificateTimestamps
	httpl.fields["TLS.OCSPResponse"] = req.TLS.OCSPResponse
}

func (httpl *HTTPLogger) addTLSCertInfo(req *http.Request, logLevel uint32) {
	httpl.fields["TLS.PeerCertificates"] = req.TLS.PeerCertificates
	httpl.fields["TLS.VerifiedChains"] = req.TLS.VerifiedChains
}

func (httpl *HTTPLogger) addPredictedResponce(req *http.Request, logLevel uint32) {
	httpl.fields["Response"] = req.Response
}

func (httpl *HTTPLogger) deleteFieldIfPresent(name string) {
	_, ok := httpl.fields[name]
	if ok {
		delete(httpl.fields, name)
	}
}
