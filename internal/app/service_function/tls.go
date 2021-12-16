package service_function

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
