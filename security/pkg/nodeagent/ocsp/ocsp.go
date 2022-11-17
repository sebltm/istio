package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
)

var (
	ocspLog         = log.RegisterScope("ocsp", "ocsp debugging", 0)
	ctx             = context.Background()
	timeoutDuration = 5 * time.Second
)

func GenerateOcspStaple(OcspMode security.OcspMode, certBytes []byte) ([]byte, error) {
	var ocspResponse []byte

	cert, err := decodePem(certBytes)
	if err != nil {
		return ocspResponse, err
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		return ocspResponse, err
	}

	ocspLog.Debugf("Received the issuer certificate")

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return ocspResponse, fmt.Errorf("couldn't create OCSP request: %s", err)

	}

	ocspLog.Debugf("Created the OCSP request")

	ocspStaple, err := sendOcspRequest(cert.OCSPServer[0], buffer)
	if err != nil {
		return ocspResponse, fmt.Errorf("failed to send OCSP request: %s", err)
	}

	ocspLog.Debugf("Received the OCSP response")

	return ocspStaple, nil
}

func CheckOcspExpired(rawStaple []byte, rawCertChain []byte) bool {
	cert, err := decodePem(rawCertChain)
	if err != nil {
		ocspLog.Warn("failed to decode PEM")
		return true
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		ocspLog.Warn("failed to get issuer certificate")
		return true
	}

	staple, err := ocsp.ParseResponse(rawStaple, issuer)
	if err != nil {
		ocspLog.Warnf("error while parsing the staple: %s", err)
		return true
	}

	if staple.NextUpdate.After(time.Now()) {
		return true
	}

	return false
}

// decodePem: decode the bytes of a certificate chain into a x509 certificate
func decodePem(certInput []byte) (*x509.Certificate, error) {
	var certDERBlock *pem.Block
	certDERBlock, _ = pem.Decode(certInput)

	if certDERBlock == nil {
		return nil, fmt.Errorf("didn't find a PEM block")
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	return cert, err
}

// getIssuerCert: given a cert, find its issuer certificate
func getIssuerCert(ctx context.Context, url string) (*x509.Certificate, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting cert from %s: %w", url, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert, nil
}

// sendOcspRequest: send an OCSP request and return the staple
func sendOcspRequest(leafOcsp string, buffer []byte) ([]byte, error) {
	httpRequest, err := http.NewRequest(http.MethodPost, leafOcsp, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, err
	}
	ocspURL, err := url.Parse(leafOcsp)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	return output, nil
}
