package service_function

import (
    "net/http"
    "fmt"
    "time"

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

    fmt.Printf("--->> %20s", "Host\n")

    fmt.Printf("--->> %20s", "Form\n")

    fmt.Printf("--->> %20s", "PostForm\n")

    fmt.Printf("--->> %20s", "MultipartForm\n")

    fmt.Printf("--->> %20s", "Trailer\n")

    fmt.Printf("--->> %20s", "RemoteAddr\n")

    fmt.Printf("--->> %20s", "RequestURI\n")

    fmt.Printf("--->> %20s", "TLS\n")

    fmt.Printf("--->> %20s", "Cancel\n")

    fmt.Printf("--->> %20s", "Response\n")




    
    
    
    
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
