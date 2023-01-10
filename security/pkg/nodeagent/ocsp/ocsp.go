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
	"google.golang.org/protobuf/types/known/durationpb"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
)

var (
	ocspLog            = log.RegisterScope("ocsp", "ocsp debugging", 0)
	ctx                = context.Background()
	timeoutDuration    = 5 * time.Second
	contentType        = "Content-Type"
	ocspRequestType    = "application/ocsp-request"
	ocspResponseType   = "application/ocsp-response"
	accept             = "Accept"
	host               = "host"
	ocspClientInstance *OcspClient
)

type OcspClient struct {
	kubeclient     *dynamic.NamespaceableResourceInterface
	certOcspStaple map[string]OcspStaple
}

type OcspStaple struct {
	RawStaple []byte
	CertBytes []byte
	Namespace string
	OcspMode  security.OcspMode
	Ttl       time.Duration
}

func GetOcspClient() *OcspClient {
	if ocspClientInstance != nil {
		return ocspClientInstance
	}
	ocspClientInstance = &OcspClient{}

	kubeclient := ocspClientInstance.getKubeOcspClient()
	ocspClientInstance.kubeclient = &kubeclient

	ocspClientInstance.certOcspStaple = make(map[string]OcspStaple)

	existingOcspStaples, err := ocspClientInstance.listOcspStaples()
	if err != nil {
		ocspLog.Errorf("Failed to populate existing OCSP Staples: %s", err)
	}
	for _, ocspStaple := range existingOcspStaples {
		name := ocspStaple.GetCertificateName()
		ocspClientInstance.certOcspStaple[name] = OcspStaple{
			RawStaple: ocspStaple.GetStaple(),
			Ttl:       ocspStaple.GetTtl().AsDuration(),
		}
	}

	return ocspClientInstance
}

func (c OcspClient) newController() *kube.Client {
	config, err := rest.InClusterConfig()
	if err != nil {
		ocspLog.Errorf("Could not get istiod incluster configuration: %v", err)
		return nil
	}
	ocspLog.Info("Successfully retrieved incluster config.")

	localKubeClient, err := kube.NewClient(kube.NewClientConfigForRestConfig(config))
	if err != nil {
		ocspLog.Errorf("Could not create a client to access local cluster API server: %v", err)
		return nil
	}
	ocspLog.Infof("Successfully created in cluster kubeclient at %s", localKubeClient.RESTConfig().Host)

	return &localKubeClient
}

func (c OcspClient) getKubeOcspClient() dynamic.NamespaceableResourceInterface {
	if c.kubeclient != nil {
		return *c.kubeclient
	}

	kubeclient := c.newController()
	if kubeclient == nil {
		return nil
	}

	ocspStaplesResource := collections.IstioNetworkingV1Alpha3Ocspstaples.Resource()
	ocspClient := (*kubeclient).Dynamic().Resource(ocspStaplesResource.GroupVersionResource())
	c.kubeclient = &ocspClient
	return *c.kubeclient
}

func (c OcspClient) MonitorOcspStaples() {
	for certName, ocspStaple := range c.certOcspStaple {
		if ocspStaple.RawStaple == nil || len(ocspStaple.RawStaple) == 0 || HasOcspStapleExpired(ocspStaple.RawStaple, ocspStaple.CertBytes) {
			c.generateOcspStaple(ocspStaple.OcspMode, certName, ocspStaple.Namespace, ocspStaple.CertBytes)
		}
	}
}

func (c OcspClient) RequestOcspStaple(OcspMode security.OcspMode, certName string, certNamespace string, certBytes []byte) OcspStaple {
	_, ok := c.certOcspStaple[certName]
	if !ok {
		c.certOcspStaple[certName] = OcspStaple{
			OcspMode:  OcspMode,
			Namespace: certNamespace,
		}
	}

	return c.certOcspStaple[certName]
}

func (c OcspClient) generateOcspStaple(OcspMode security.OcspMode, certName string, certNamespace string, certBytes []byte) ([]byte, error) {
	existingStaple, ok := c.certOcspStaple[certName]
	if ok {
		if !HasOcspStapleExpired(existingStaple.RawStaple, certBytes) {
			return existingStaple.RawStaple, nil
		}
	}

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

	ocspResponse, err = c.sendOcspRequest(cert.OCSPServer[0], buffer)
	if err != nil {
		return ocspResponse, fmt.Errorf("failed to send OCSP request: %s", err)
	}

	ocspLog.Debugf("Received the OCSP response")

	ocspStaple, err := ocsp.ParseResponse(ocspResponse, issuer)
	if err != nil {
		ocspLog.Warnf("error while parsing the staple: %s", err)
		return make([]byte, 0), nil
	}
	ttl := time.Until(ocspStaple.NextUpdate)
	c.writeOcspStaple(ocspStaple.Raw, ttl, certName, certName, certNamespace)

	return ocspStaple.Raw, nil
}

func HasOcspStapleExpired(rawStaple []byte, rawCertChain []byte) bool {
	ocspStapleExpired := true

	cert, err := decodePem(rawCertChain)
	if err != nil {
		ocspLog.Warn("failed to decode PEM")
		return ocspStapleExpired
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		ocspLog.Warn("failed to get issuer certificate")
		return ocspStapleExpired
	}

	staple, err := ocsp.ParseResponse(rawStaple, issuer)
	if err != nil {
		ocspLog.Warnf("error while parsing the staple: %s", err)
		return ocspStapleExpired
	}

	if staple.NextUpdate.After(time.Now()) {
		return ocspStapleExpired
	}

	ocspStapleExpired = false
	return ocspStapleExpired
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

// sendOcspRequest: send an OCSP request, write the and return the staple
func (c OcspClient) sendOcspRequest(leafOcsp string, buffer []byte) ([]byte, error) {
	httpRequest, err := http.NewRequest(http.MethodPost, leafOcsp, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, err
	}
	ocspURL, err := url.Parse(leafOcsp)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add(contentType, ocspRequestType)
	httpRequest.Header.Add(accept, ocspResponseType)
	httpRequest.Header.Add(host, ocspURL.Host)

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

func (c OcspClient) listOcspStaples() ([]*v1alpha3.OCSPStaple, error) {
	ocspClient := c.getKubeOcspClient()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	unstructStapleList, err := ocspClient.Namespace("").List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to find list of staples")
	}

	ocspStapleList := make([]*v1alpha3.OCSPStaple, len(unstructStapleList.Items))

	for i, unstructStapleObject := range unstructStapleList.Items {
		stapleObject := &v1alpha3.OCSPStaple{}
		err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructStapleObject.Object, stapleObject)
		ocspLog.Errorf("failed to convert unstructured staple object into OCSPStaple %s in namespace %s: %s", unstructStapleObject.GetName(), unstructStapleObject.GetNamespace(), err)
		ocspStapleList[i] = stapleObject
	}

	return ocspStapleList, nil
}

func (c OcspClient) readOcspStaple(stapleName string, namespace string) (*v1alpha3.OCSPStaple, error) {
	ocspClient := c.getKubeOcspClient()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	unstructStapleObject, err := ocspClient.Namespace(namespace).Get(ctx, stapleName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to find staple %s in namespace %s: %s", stapleName, namespace, err)
	}

	stapleObject := &v1alpha3.OCSPStaple{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructStapleObject.Object, stapleObject)
	if err != nil {
		return nil, fmt.Errorf("failed to convert unstructured staple object into OCSPStaple %s in namespace %s: %s", stapleName, namespace, err)
	}

	return stapleObject, nil
}

func (c OcspClient) writeOcspStaple(staple []byte, ttl time.Duration, certificateName string, stapleName string, namespace string) error {
	ocspClient := c.getKubeOcspClient()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	createStaple := false
	stapleObject, err := c.readOcspStaple(stapleName, namespace)
	if err != nil {
		createStaple = true
		stapleObject = &v1alpha3.OCSPStaple{}
	}

	stapleObject.Staple = staple
	stapleObject.Ttl = durationpb.New(ttl)
	stapleObject.CertificateName = certificateName

	unstructuredStapleContent, err := runtime.DefaultUnstructuredConverter.ToUnstructured(stapleObject)
	unstructuredStaple := unstructured.Unstructured{}

	ocspStaplesResource := collections.IstioNetworkingV1Alpha3Ocspstaples.Resource()
	unstructuredStaple.SetGroupVersionKind(ocspStaplesResource.GroupVersionKind().Kubernetes())
	unstructuredStaple.SetUnstructuredContent(unstructuredStapleContent)
	unstructuredStaple.SetName(stapleName)

	if err != nil {
		return fmt.Errorf("failed to convert from staple %s in namespace %s to unstructured object", stapleName, namespace)
	}

	if createStaple {
		_, err := ocspClient.Namespace(namespace).Update(ctx, &unstructuredStaple, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update staple %s in namespace %s: %s", stapleName, namespace, err)
		}
	} else {
		_, err := ocspClient.Namespace(namespace).Create(ctx, &unstructuredStaple, v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create staple %s in namespace %s: %s", stapleName, namespace, err)
		}
	}

	c.certOcspStaple[certificateName] = OcspStaple{
		RawStaple: staple,
		Ttl:       ttl,
	}

	return nil
}
