# ztsfc_http_sf_logger
service function that can log all forwarded packets in different granularity

## Parameters
#### Custom path to config file
`-c path_to_config_file` (srting)

User can provide a custom path to the Service Function configuration file.

Defalut value: "./conf.yml"

#### Log level for system messages (partially implemented)
`-l logLevel` (int)

The Logger SF can include own system messages in the log output.

Supported values: `[0..3]` ( NONE | BASIC | ADVANCED | DEBUG )

#### Optional redirection the SF log output to files.
`-log-to-file` (bool)

The parameter doesn't have a value.

Default value of a log file is "./access.log" but also can be set with a function getLogFilePath(), that is called during a new logWriter instance creation.

Example of getLogFilePath() function:
```
func getLogFilePath() string {
    t := time.Now()
    // Format time stamp
    logFileName := fmt.Sprintf("sf-logger-%4d-%02d-%02d-%02d.log",
                                          t.Year(),
                                              t.Month(),
                                                   t.Day(),
                                                        t.Hour())
    return logFileName
}
```
The example will create new log files every hour, but this could be easily changed.

### Example
`sudo ./ztsfc_http_sf_logger -c /opt/logger.yml -l 3 -log-to-file`

## HTTP requests logging levels
The logging levels are organized as a bit mask (4 bytes) with the next values:
```
    SFLOGGER_REGISTER_PACKETS_ONLY      0x00000001
    SFLOGGER_PRINT_GENERAL_INFO         0x00000002
    SFLOGGER_PRINT_HEADER_FIELDS        0x00000004
    SFLOGGER_PRINT_TRAILERS             0x00000008
    SFLOGGER_PRINT_BODY                 0x00000010
    SFLOGGER_PRINT_FORMS                0x00000020
    SFLOGGER_PRINT_FORMS_FILE_CONTENT   0x00000040
    SFLOGGER_PRINT_TLS_MAIN_INFO        0x00000080
    SFLOGGER_PRINT_TLS_CERTIFICATES     0x00000100
    SFLOGGER_PRINT_TLS_PUBLIC_KEY       0x00000200
    SFLOGGER_PRINT_TLS_CERT_SIGNATURE   0x00000400
    SFLOGGER_PRINT_RAW                  0x00000800
    SFLOGGER_PRINT_REDIRECTED_RESPONSE  0x00001000
    SFLOGGER_PRINT_EMPTY_FIELDS         0x00002000
```
The SF Logger gets the logging level value in the "Sfloggerlevel" HTTP header and deletes the header before forwarding to the next SF in the chain or to a target service.
