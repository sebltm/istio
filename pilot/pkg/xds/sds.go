// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	cryptomb "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/private_key_providers/cryptomb/v3alpha"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoytls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	mesh "istio.io/api/mesh/v1alpha1"
	networking "istio.io/api/networking/v1alpha3"
	credscontroller "istio.io/istio/pilot/pkg/credentials"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/model/credentials"
	securitymodel "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/nodeagent/ocsp"
)

// SecretResource wraps the authnmodel type with cache functions implemented
type SecretResource struct {
	credentials.SecretResource
}

var (
	_                   model.XdsCacheEntry = SecretResource{}
	OcspStaplingEnabled string              = "ocspStaplingEnabled"
	OcspStaplingMode    string              = "ocspStaplingMode"
)

// DependentTypes is not needed; we know exactly which configs impact SDS, so we can scope at DependentConfigs level
func (sr SecretResource) DependentTypes() []kind.Kind {
	return nil
}

func (sr SecretResource) DependentConfigs() []model.ConfigHash {
	configs := []model.ConfigHash{}
	for _, config := range relatedConfigs(model.ConfigKey{Kind: kind.Secret, Name: sr.Name, Namespace: sr.Namespace}) {
		configs = append(configs, config.HashCode())
	}
	return configs
}

func (sr SecretResource) Cacheable() bool {
	return true
}

func sdsNeedsPush(updates model.XdsUpdates) bool {
	if len(updates) == 0 {
		return true
	}
	if model.ConfigsHaveKind(updates, kind.Secret) ||
		model.ConfigsHaveKind(updates, kind.OCSPStaple) ||
		model.ConfigsHaveKind(updates, kind.Gateway) ||
		model.ConfigsHaveKind(updates, kind.ReferencePolicy) ||
		model.ConfigsHaveKind(updates, kind.ReferenceGrant) {
		return true
	}
	return false
}

// parseResources parses a list of resource names to SecretResource types, for a given proxy.
// Invalid resource names are ignored
func (s *SecretGen) parseResources(names []string, proxy *model.Proxy) []SecretResource {
	res := make([]SecretResource, 0, len(names))
	for _, resource := range names {
		sr, err := credentials.ParseResourceName(resource, proxy.VerifiedIdentity.Namespace, proxy.Metadata.ClusterID, s.configCluster)
		if err != nil {
			pilotSDSCertificateErrors.Increment()
			log.Warnf("error parsing resource name: %v", err)
			continue
		}
		res = append(res, SecretResource{sr})
	}
	return res
}

func (s *SecretGen) Generate(proxy *model.Proxy, w *model.WatchedResource, req *model.PushRequest) (model.Resources, model.XdsLogDetails, error) {
	if proxy.VerifiedIdentity == nil {
		log.Warnf("proxy %s is not authorized to receive credscontroller. Ensure you are connecting over TLS port and are authenticated.", proxy.ID)
		return nil, model.DefaultXdsLogDetails, nil
	}
	if req == nil || !sdsNeedsPush(req.ConfigsUpdated) {
		return nil, model.DefaultXdsLogDetails, nil
	}
	var updatedSecrets map[model.ConfigKey]struct{}
	if !req.Full {
		updatedSecrets = model.ConfigsOfKind(req.ConfigsUpdated, kind.Secret)
	}

	// TODO: For the new gateway-api, we should always search the config namespace and stop reading across all clusters
	proxyClusterSecrets, err := s.secrets.ForCluster(proxy.Metadata.ClusterID)
	if err != nil {
		log.Warnf("proxy %s is from an unknown cluster, cannot retrieve certificates: %v", proxy.ID, err)
		pilotSDSCertificateErrors.Increment()
		return nil, model.DefaultXdsLogDetails, nil
	}
	configClusterSecrets, err := s.secrets.ForCluster(s.configCluster)
	if err != nil {
		log.Warnf("config cluster %s not found, cannot retrieve certificates: %v", s.configCluster, err)
		pilotSDSCertificateErrors.Increment()
		return nil, model.DefaultXdsLogDetails, nil
	}

	// Filter down to secretResources we can access. We do not return an error if they attempt to access a Secret
	// they cannot; instead we just exclude it. This ensures that a single bad reference does not break the whole
	// SDS flow. The pilotSDSCertificateErrors metric and logs handle visibility into invalid references.
	secretResources := filterAuthorizedResources(s.parseResources(w.ResourceNames, proxy), proxy, proxyClusterSecrets)
	// Fetch additional attributes for these resources (e.g whether OCSP stapling is enabled)
	certResourceMap := s.certToResource(proxy)
	for i, resource := range secretResources {
		log.Infof("secret resource name: %s", resource.Name)

		additionalAttributes := s.compileAdditionalAttributes(certResourceMap, resource)
		resource.AddAdditionalAttributes(additionalAttributes)
		secretResources[i] = resource
	}

	results := model.Resources{}
	cached, regenerated := 0, 0
	for _, sr := range secretResources {
		cachedItem, f := s.cache.Get(sr)
		if f && !features.EnableUnsafeAssertions && isValidOcspStaple(sr, *cachedItem) {
			// If it is in the Cache, add it and continue
			// We skip cache if assertions are enabled, so that the cache will assert our eviction logic is correct
			log.Warnf("ocsp: for resource %s, using cached", sr.Name)

			results = append(results, cachedItem)
			cached++
			continue
		}
		log.Warnf("ocsp: for resource %s, regenerating", sr.Name)
		regenerated++
		res := s.generate(sr, configClusterSecrets, proxyClusterSecrets, proxy)
		if res != nil {
			s.cache.Add(sr, req, res)
			results = append(results, res)
		}
	}
	return results, model.XdsLogDetails{
		Incremental:    updatedSecrets != nil,
		AdditionalInfo: fmt.Sprintf("cached:%v/%v", cached, cached+regenerated),
	}, nil
}

func (s *SecretGen) certToResource(proxy *model.Proxy) map[string]*networking.Server {
	certToServer := make(map[string]*networking.Server)

	gateways := proxy.MergedGateway
	if gateways == nil {
		log.Warnf("No Gateways for proxy on %+v", proxy.Metadata.InstanceIPs)
		return certToServer
	}

	serverPorts := gateways.ServerPorts
	if serverPorts == nil {
		log.Infof("Gateways for proxy on %+v have no server ports defined", proxy.Metadata.InstanceIPs)
		return certToServer
	}

	// Get a mapping of certificate resource name (e.g Kubernetes Secret) to Server
	for _, serverPort := range serverPorts {

		mergedServers, ok := gateways.MergedServers[serverPort]
		if !ok || mergedServers == nil {
			log.Warnf("gateway has no servers for port %d", serverPort)
			continue
		}

		for _, server := range mergedServers.Servers {
			if server == nil || server.Tls == nil {
				continue
			}
			certToServer[server.Tls.CredentialName] = server
		}
	}

	return certToServer
}

func (s *SecretGen) compileAdditionalAttributes(certToServer map[string]*networking.Server, sr SecretResource) map[string]interface{} {
	additionalAttributes := make(map[string]interface{})

	// Find the Server associated with the resource and fetch additional attributes
	server, ok := certToServer[sr.Name]
	if !ok {
		log.Warnf("no server for resource %s", sr.Name)
		return additionalAttributes
	}

	serverTls := server.Tls
	if serverTls == nil {
		log.Warnf("server for resource %s has no TLS settings", sr.Name)
		return additionalAttributes
	}

	if serverTls.Ocsp != nil && serverTls.Ocsp.Stapling != nil {
		additionalAttributes[OcspStaplingEnabled] = serverTls.Ocsp.Stapling.Enabled
		additionalAttributes[OcspStaplingMode] = serverTls.Ocsp.Stapling.Mode
	}

	return additionalAttributes
}

func (s *SecretGen) generate(sr SecretResource, configClusterSecrets, proxyClusterSecrets credscontroller.Controller, proxy *model.Proxy) *discovery.Resource {
	// Fetch the appropriate cluster's secret, based on the credential type
	var secretController credscontroller.Controller
	switch sr.Type {
	case credentials.KubernetesGatewaySecretType:
		secretController = configClusterSecrets
	default:
		secretController = proxyClusterSecrets
	}

	isCAOnlySecret := strings.HasSuffix(sr.Name, securitymodel.SdsCaSuffix)
	if isCAOnlySecret {
		caCert, err := secretController.GetCaCert(sr.Name, sr.Namespace)
		if err != nil {
			pilotSDSCertificateErrors.Increment()
			log.Warnf("failed to fetch ca certificate for %s: %v", sr.ResourceName, err)
			return nil
		}
		if features.VerifySDSCertificate {
			if err := validateCertificate(caCert); err != nil {
				recordInvalidCertificate(sr.ResourceName, err)
				return nil
			}
		}
		res := toEnvoyCaSecret(sr.ResourceName, caCert)
		return res
	}

	key, cert, err := secretController.GetKeyAndCert(sr.Name, sr.Namespace)
	if err != nil {
		pilotSDSCertificateErrors.Increment()
		log.Warnf("failed to fetch key and certificate for %s: %v", sr.ResourceName, err)
		return nil
	}
	if features.VerifySDSCertificate {
		if err := validateCertificate(cert); err != nil {
			recordInvalidCertificate(sr.ResourceName, err)
			return nil
		}
	}

	// Fetch an OCSP staple
	ocspStaple := &ocsp.OcspStaple{
		RawStaple: make([]byte, 0),
	}

	if isOcspEnabled(sr) {
		log.Warnf("for resource %s, OCSP stapling is enabled", sr.Name)
		// Check the OCSP Stapling Mode
		// Default is Mandatory
		staplingModeRaw, ok := sr.GetAdditionalAttribute(OcspStaplingMode).(string)
		if !ok {
			staplingModeRaw = "Mandatory"
		}

		staplingMode, err := security.ParseOcspMode(staplingModeRaw)
		if err != nil {
			staplingMode = security.Mandatory
			log.Warnf("%s", err)
		}

		ocspHandler := ocsp.GetOcspClient()
		ocspStaple, err = ocspHandler.RequestOcspStaple(staplingMode, sr.Name, sr.Namespace, cert)
		if err != nil {
			pilotSDSCertificateErrors.Increment()
			log.Warnf("failed to fetch OCSP staple for %s: %v", sr.ResourceName, err)
			return nil
		}
	}

	res := toEnvoyKeyCertSecret(sr.ResourceName, key, cert, ocspStaple.RawStaple, proxy, s.meshConfig)
	return res
}

func isOcspEnabled(sr SecretResource) bool {
	// Check whether stapling is enabled for this certificate
	// Default is to disable OCSP Stapling
	staplingEnabled, ok := sr.GetAdditionalAttribute(OcspStaplingEnabled).(bool)
	if !ok {
		staplingEnabled = false
	}

	return staplingEnabled
}

func isValidOcspStaple(sr SecretResource, resource discovery.Resource) bool {
	res := resource.GetResource()
	envoySecret := envoytls.Secret{}
	err := res.UnmarshalTo(&envoySecret)
	if err != nil {
		log.Warnf("failed to get Envoy Secret from resource")
	}

	tlsCertificate := envoySecret.GetTlsCertificate()

	if tlsCertificate != nil {
		emptyStaple := (tlsCertificate.OcspStaple.GetInlineBytes() == nil || len(tlsCertificate.OcspStaple.GetInlineBytes()) == 0) && len(tlsCertificate.OcspStaple.GetInlineString()) == 0
		emptyCert := tlsCertificate.CertificateChain.GetInlineBytes() == nil || len(tlsCertificate.CertificateChain.GetInlineBytes()) == 0

		if !isOcspEnabled(sr) && emptyStaple {
			// if OCSP stapling is disabled and the staple is empty, then consider valid
			log.Warnf("Resource %s has OCSP staple disabled and no staple", sr.Name)
			return true
		} else if !isOcspEnabled(sr) && !emptyStaple {
			// if there is an OCSP staple but stapling is disabled, then not valid
			log.Warnf("Resource %s has OCSP staple disabled but we found a staple", sr.Name)
			return false
		} else if isOcspEnabled(sr) && (emptyCert || emptyStaple) {
			// if OCSP staple is requested but either the cert is empty or the staple is empty, then also not valid
			log.Warnf("Resource %s has OCSP staple enabled but we found no staple or certificate", sr.Name)
			return false
		}

		expiredStaple, _ := ocsp.HasOcspStapleExpired(tlsCertificate.OcspStaple.GetInlineBytes(), tlsCertificate.CertificateChain.GetInlineBytes())
		return !expiredStaple
	}

	return true
}

func validateCertificate(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("pem decode failed")
	}
	_, err := x509.ParseCertificates(block.Bytes)
	return err
}

func recordInvalidCertificate(name string, err error) {
	pilotSDSCertificateErrors.Increment()
	log.Warnf("invalid certificates: %q: %v", name, err)
}

// filterAuthorizedResources takes a list of SecretResource and filters out resources that proxy cannot access
func filterAuthorizedResources(resources []SecretResource, proxy *model.Proxy, secrets credscontroller.Controller) []SecretResource {
	var authzResult *bool
	var authzError error
	// isAuthorized is a small wrapper around credscontroller.Authorize so we only call it once instead of each time in the loop
	isAuthorized := func() bool {
		if authzResult != nil {
			return *authzResult
		}
		res := false
		if err := secrets.Authorize(proxy.VerifiedIdentity.ServiceAccount, proxy.VerifiedIdentity.Namespace); err == nil {
			res = true
		} else {
			authzError = err
		}
		authzResult = &res
		return res
	}

	// There are 4 cases of secret reference
	// Verified cross namespace (by ReferencePolicy). No Authz needed.
	// Verified same namespace (implicit). No Authz needed.
	// Unverified cross namespace. Never allowed.
	// Unverified same namespace. Allowed if authorized.
	allowedResources := make([]SecretResource, 0, len(resources))
	deniedResources := make([]string, 0)
	for _, r := range resources {
		sameNamespace := r.Namespace == proxy.VerifiedIdentity.Namespace
		verified := proxy.MergedGateway != nil && proxy.MergedGateway.VerifiedCertificateReferences.Contains(r.ResourceName)
		switch r.Type {
		case credentials.KubernetesGatewaySecretType:
			// For KubernetesGateway, we only allow VerifiedCertificateReferences.
			// This means a Secret in the same namespace as the Gateway (which also must be in the same namespace
			// as the proxy), or a ReferencePolicy allowing the reference.
			if verified {
				allowedResources = append(allowedResources, r)
			} else {
				deniedResources = append(deniedResources, r.Name)
			}
		case credentials.KubernetesSecretType:
			// For Kubernetes, we require the secret to be in the same namespace as the proxy and for it to be
			// authorized for access.
			if sameNamespace && isAuthorized() {
				allowedResources = append(allowedResources, r)
			} else {
				deniedResources = append(deniedResources, r.Name)
			}
		default:
			// Should never happen
			log.Warnf("unknown credential type %q", r.Type)
			pilotSDSCertificateErrors.Increment()
		}
	}

	// If we filtered any out, report an error. We aggregate errors in one place here, rather than in the loop,
	// to avoid excessive logs.
	if len(deniedResources) > 0 {
		errMessage := authzError
		if errMessage == nil {
			errMessage = fmt.Errorf("cross namespace secret reference requires ReferencePolicy")
		}
		log.Warnf("proxy %s attempted to access unauthorized certificates %s: %v", proxy.ID, atMostNJoin(deniedResources, 3), errMessage)
		pilotSDSCertificateErrors.Increment()
	}

	return allowedResources
}

func atMostNJoin(data []string, limit int) string {
	if limit == 0 || limit == 1 {
		// Assume limit >1, but make sure we dpn't crash if someone does pass those
		return strings.Join(data, ", ")
	}
	if len(data) == 0 {
		return ""
	}
	if len(data) < limit {
		return strings.Join(data, ", ")
	}
	return strings.Join(data[:limit-1], ", ") + fmt.Sprintf(", and %d others", len(data)-limit+1)
}

func toEnvoyCaSecret(name string, cert []byte) *discovery.Resource {
	res := protoconv.MessageToAny(&envoytls.Secret{
		Name: name,
		Type: &envoytls.Secret_ValidationContext{
			ValidationContext: &envoytls.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: cert,
					},
				},
			},
		},
	})
	return &discovery.Resource{
		Name:     name,
		Resource: res,
	}
}

func toEnvoyKeyCertSecret(name string, key, cert, ocsp []byte, proxy *model.Proxy, meshConfig *mesh.MeshConfig) *discovery.Resource {
	var res *anypb.Any
	pkpConf := proxy.Metadata.ProxyConfigOrDefault(meshConfig.GetDefaultConfig()).GetPrivateKeyProvider()

	switch pkpConf.GetProvider().(type) {
	case *mesh.PrivateKeyProvider_Cryptomb:
		crypto := pkpConf.GetCryptomb()
		msg := protoconv.MessageToAny(&cryptomb.CryptoMbPrivateKeyMethodConfig{
			PollDelay: durationpb.New(time.Duration(crypto.GetPollDelay().Nanos)),
			PrivateKey: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{
					InlineBytes: key,
				},
			},
		})
		res = protoconv.MessageToAny(&envoytls.Secret{
			Name: name,
			Type: &envoytls.Secret_TlsCertificate{
				TlsCertificate: &envoytls.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: cert,
						},
					},
					PrivateKeyProvider: &envoytls.PrivateKeyProvider{
						ProviderName: "cryptomb",
						ConfigType: &envoytls.PrivateKeyProvider_TypedConfig{
							TypedConfig: msg,
						},
					},
					OcspStaple: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: ocsp,
						},
					},
				},
			},
		})
	default:
		res = protoconv.MessageToAny(&envoytls.Secret{
			Name: name,
			Type: &envoytls.Secret_TlsCertificate{
				TlsCertificate: &envoytls.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: cert,
						},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: key,
						},
					},
					OcspStaple: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: ocsp,
						},
					},
				},
			},
		})
	}
	return &discovery.Resource{
		Name:     name,
		Resource: res,
	}
}

func containsAny(mp map[model.ConfigKey]struct{}, keys []model.ConfigKey) bool {
	for _, k := range keys {
		if _, f := mp[k]; f {
			return true
		}
	}
	return false
}

// relatedConfigs maps a single resource to a list of relevant resources. This is used for cache invalidation
// and push skipping. This is because an secret potentially has a dependency on the same secret with or without
// the -cacert suffix. By including this dependency we ensure we do not miss any updates.
// This is important for cases where we have a compound secret. In this case, the `foo` secret may update,
// but we need to push both the `foo` and `foo-cacert` resource name, or they will fall out of sync.
func relatedConfigs(k model.ConfigKey) []model.ConfigKey {
	related := []model.ConfigKey{k}
	// For secret without -cacert suffix, add the suffix
	if !strings.HasSuffix(k.Name, securitymodel.SdsCaSuffix) {
		k.Name += securitymodel.SdsCaSuffix
		related = append(related, k)
	} else {
		// For secret with -cacert suffix, remove the suffix
		k.Name = strings.TrimSuffix(k.Name, securitymodel.SdsCaSuffix)
		related = append(related, k)
	}
	return related
}

type SecretGen struct {
	secrets credscontroller.MulticlusterController
	// Cache for XDS resources
	cache         model.XdsCache
	configCluster cluster.ID
	meshConfig    *mesh.MeshConfig
}

var _ model.XdsResourceGenerator = &SecretGen{}

func NewSecretGen(sc credscontroller.MulticlusterController, cache model.XdsCache, configCluster cluster.ID,
	meshConfig *mesh.MeshConfig,
) *SecretGen {
	// TODO: Currently we only have a single credentials controller (Kubernetes). In the future, we will need a mapping
	// of resource type to secret controller (ie kubernetes:// -> KubernetesController, vault:// -> VaultController)
	return &SecretGen{
		secrets:       sc,
		cache:         cache,
		configCluster: configCluster,
		meshConfig:    meshConfig,
	}
}
