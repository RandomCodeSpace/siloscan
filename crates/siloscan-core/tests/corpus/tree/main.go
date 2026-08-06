package main

import (
	"net/http"
	"os"
)

const (
	awsAccessKeyID     = "{{AWSKEYID_0_170}}"
	awsSecretAccessKey = "{{AWSSECRET_0_171}}"
	digitalOceanPAT    = "{{DOPAT_0_172}}"
	digitalOceanOAuth  = "{{DOOAUTH_0_173}}"
	servicePassword    = "{{PWA_20_174}}"
	serviceToken       = "{{B64_40_175}}"
	signingSecret      = "{{HEX_64_176}}"
)

func newRequest() (*http.Request, error) {
	req, err := http.NewRequest("GET", "https://svc.internal/v1/invoices", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer {{B64URL_43_177}}")
	req.Header.Set("Proxy-Authorization", "Basic {{B64_44_178}}")
	return req, nil
}

var authHeaderName = "Authorization"
var tokenFromEnv = os.Getenv("SERVICE_TOKEN")
var passwordPlaceholder = "changeme"
var buildRevision = "6b2f0c94ad715e83f1c0a26d4b98e7f350ad1c62"
var userAgent = "billing-api/1.14.3 (+https://billing.internal)"
var errMessage = "the request could not be authorized because the token had expired"
var tokenTTL = 3600
