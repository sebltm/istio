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
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/types/known/durationpb"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	clientnetworking "istio.io/client-go/pkg/apis/networking/v1alpha3"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
)

var (
	ocspLog            = log.RegisterScope("ocsp", "ocsp debugging", 0)
	ctx                = context.Background()
	timeoutDuration    = 5 * time.Second
	gracePeriod        = 24 * time.Hour
	contentType        = "Content-Type"
	ocspRequestType    = "application/ocsp-request"
	ocspResponseType   = "application/ocsp-response"
	accept             = "Accept"
	host               = "host"
	allNamespaces      = ""
	ocspClientInstance *OcspClient
)

type OcspClient struct {
	kubeclient     *dynamic.NamespaceableResourceInterface
	certOcspStaple map[string]OcspStaple
	lock           *sync.Mutex
}

type OcspStaple struct {
	RawStaple       []byte
	CertBytes       []byte
	Namespace       string
	CertificateName string
	Name            string
	OcspMode        security.OcspMode
	Ttl             time.Duration
}

func GetOcspClient() *OcspClient {
	if ocspClientInstance != nil {
		return ocspClientInstance
	}
	ocspClientInstance = &OcspClient{}

	ocspClientInstance.lock = &sync.Mutex{}

	kubeclient := ocspClientInstance.getKubeOcspClient()
	ocspClientInstance.kubeclient = &kubeclient

	ocspClientInstance.certOcspStaple = make(map[string]OcspStaple)

	ocspStapleList, err := ocspClientInstance.listOcspStaples(allNamespaces)
	if err != nil {
		ocspLog.Errorf("failed to populate existing OCSP Staples: %s", err)
	}
	ocspLog.Warnf("found list of OCSP staples: %+v", ocspStapleList)
	for _, ocspStaple := range ocspStapleList.Items {
		name := ocspStaple.Spec.GetCertificateName()
		ocspClientInstance.certOcspStaple[name] = OcspStaple{
			RawStaple: ocspStaple.Spec.GetStaple(),
			Ttl:       ocspStaple.Spec.GetTtl().AsDuration(),
		}
	}

	return ocspClientInstance
}

func (c OcspClient) newController() *kube.Client {
	config, err := rest.InClusterConfig()
	if err != nil {
		ocspLog.Errorf("could not get istiod incluster configuration: %v", err)
		return nil
	}
	ocspLog.Info("successfully retrieved incluster config.")

	localKubeClient, err := kube.NewClient(kube.NewClientConfigForRestConfig(config))
	if err != nil {
		ocspLog.Errorf("could not create a client to access local cluster API server: %v", err)
		return nil
	}
	ocspLog.Infof("successfully created in cluster kubeclient at %s", localKubeClient.RESTConfig().Host)

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
	for {
		for certName, ocspStaple := range c.certOcspStaple {
			if len(ocspStaple.CertBytes) == 0 {
				// no cert info, skip
				continue
			}

			expired, ttl := HasOcspStapleExpired(ocspStaple.RawStaple, ocspStaple.CertBytes)
			if ocspStaple.RawStaple == nil || len(ocspStaple.RawStaple) == 0 || expired {
				_, err := c.generateOcspStaple(ocspStaple.OcspMode, certName, ocspStaple.Namespace, ocspStaple.CertBytes)
				ocspLog.Warnf("failed to generate OCSP staple while monitoring OCSP Staples: %s", err)
			} else {
				// update the TTL
				c.writeOcspStaple(ocspStaple.RawStaple, ttl, ocspStaple.CertificateName, ocspStaple.Name, ocspStaple.Namespace)
			}
		}
		time.Sleep(timeoutDuration)
	}
}

func (c OcspClient) RequestOcspStaple(OcspMode security.OcspMode, certName string, certNamespace string, certBytes []byte) (*OcspStaple, error) {
	ocspStaple, ok := c.certOcspStaple[certName]
	if !ok {
		rawStaple, err := c.generateOcspStaple(OcspMode, certName, certNamespace, certBytes)
		if err != nil {
			return nil, err
		}
		ocspStaple = OcspStaple{
			OcspMode:  OcspMode,
			Namespace: certNamespace,
			CertBytes: certBytes,
			RawStaple: rawStaple,
		}
		return &ocspStaple, nil
	}

	// update OCSP staple with latest info
	if ocspStaple.CertBytes == nil || len(ocspStaple.CertBytes) == 0 {
		ocspStaple.CertBytes = certBytes
	}
	if ocspStaple.CertificateName == "" {
		ocspStaple.CertificateName = certName
	}
	if ocspStaple.Namespace == "" {
		ocspStaple.Namespace = certNamespace
	}

	c.certOcspStaple[certName] = ocspStaple
	return &ocspStaple, nil
}

func (c OcspClient) generateOcspStaple(OcspMode security.OcspMode, certName string, certNamespace string, certBytes []byte) ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	existingStaple, ok := c.certOcspStaple[certName]
	if ok && existingStaple.RawStaple != nil && len(existingStaple.RawStaple) > 0 && len(certBytes) > 0 {
		if expired, _ := HasOcspStapleExpired(existingStaple.RawStaple, certBytes); !expired {
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

	ocspLog.Debugf("received the issuer certificate")

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return ocspResponse, fmt.Errorf("couldn't create OCSP request: %s", err)
	}

	ocspLog.Debugf("created the OCSP request")

	ocspResponse, err = c.sendOcspRequest(cert.OCSPServer[0], buffer)
	if err != nil {
		return ocspResponse, fmt.Errorf("failed to send OCSP request: %s", err)
	}

	ocspLog.Debugf("received the OCSP response")

	ocspStaple, err := ocsp.ParseResponse(ocspResponse, issuer)
	if err != nil {
		ocspLog.Warnf("error while parsing the staple: %s", err)
		return make([]byte, 0), nil
	}
	ttl := time.Until(ocspStaple.NextUpdate)
	err = c.writeOcspStaple(ocspStaple.Raw, ttl, certName, certName, certNamespace)
	if err != nil {
		ocspLog.Warnf("failed to persist OCSP staple: %s", err)
	}

	return ocspStaple.Raw, nil
}

func HasOcspStapleExpired(rawStaple []byte, rawCertChain []byte) (bool, time.Duration) {
	ocspStapleExpired := true

	cert, err := decodePem(rawCertChain)
	if err != nil {
		ocspLog.Warn("failed to decode PEM")
		return ocspStapleExpired, 0
	}

	timeout, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	issuer, err := getIssuerCert(timeout, cert.IssuingCertificateURL[0])
	if err != nil {
		ocspLog.Warn("failed to get issuer certificate")
		return ocspStapleExpired, 0
	}

	staple, err := ocsp.ParseResponse(rawStaple, issuer)
	if err != nil {
		ocspLog.Warnf("error while parsing the staple: %s", err)
		return ocspStapleExpired, 0
	}

	if staple.NextUpdate.After(time.Now().Add(-gracePeriod)) {
		return ocspStapleExpired, 0
	}

	ocspStapleExpired = false
	return ocspStapleExpired, time.Until(staple.NextUpdate)
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

func (c OcspClient) listOcspStaples(namespace string) (*clientnetworking.OCSPStapleList, error) {
	ocspClient := c.getKubeOcspClient()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	unstructStapleList, err := ocspClient.Namespace(namespace).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to find list of OCSPStaples: %s", err)
	}

	ocspStapleList := &clientnetworking.OCSPStapleList{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructStapleList.Object, ocspStapleList)
	if err != nil {
		ocspLog.Warnf("failed to convert unstructured OCSPStapleList into OCSPStapleList: %s", err)
	}

	return ocspStapleList, nil
}

func (c OcspClient) readOcspStaple(stapleName string, namespace string) (*clientnetworking.OCSPStaple, error) {
	ocspClient := c.getKubeOcspClient()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	stapleObject := &clientnetworking.OCSPStaple{}
	stapleObject.SetGroupVersionKind(collections.IstioNetworkingV1Alpha3Ocspstaples.Resource().GroupVersionKind().Kubernetes())

	unstructStapleObject, err := ocspClient.Namespace(namespace).Get(ctx, stapleName, v1.GetOptions{})
	if err != nil {
		return stapleObject, fmt.Errorf("failed to find staple %s in namespace %s: %s", stapleName, namespace, err)
	}

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
		ocspLog.Warnf("OCSP Staple %s not found in namespace %s: %s. Will attempt to create a new one", stapleName, namespace, err)
		createStaple = true
	}

	if stapleObject.GetName() == "" {
		stapleObject.Name = certificateName
	}

	stapleObject.Spec.Staple = staple
	stapleObject.Spec.Ttl = durationpb.New(ttl)
	stapleObject.Spec.CertificateName = certificateName

	unstructuredStapleContent, err := runtime.DefaultUnstructuredConverter.ToUnstructured(stapleObject)
	if err != nil {
		ocspLog.Warnf("failed to convert OCSP staple to unstructured: %s", err)
	}
	unstructuredStaple := unstructured.Unstructured{}
	unstructuredStaple.SetUnstructuredContent(unstructuredStapleContent)

	if createStaple {
		_, err := ocspClient.Namespace(namespace).Create(ctx, &unstructuredStaple, v1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create staple %s in namespace %s: %s", stapleName, namespace, err)
		}
	} else {
		_, err := ocspClient.Namespace(namespace).Update(ctx, &unstructuredStaple, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update staple %s in namespace %s: %s", stapleName, namespace, err)
		}
	}

	c.certOcspStaple[certificateName] = OcspStaple{
		RawStaple: staple,
		Ttl:       ttl,
	}

	return nil
}

func (c OcspClient) deleteOcspStaple(stapleName string, namespace string) bool {
	ocspClient := c.getKubeOcspClient()

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	_, err := c.readOcspStaple(stapleName, namespace)
	if err != nil {
		ocspLog.Warnf("unable to find OCSP staple %s in namespace %s: %s", stapleName, namespace, err)
		return false
	}

	err = ocspClient.Namespace(namespace).Delete(ctx, stapleName, v1.DeleteOptions{})
	if err != nil {
		ocspLog.Warnf("failed to delete OCSP staple %s in namespace %s")
		return false
	}

	return true
}
