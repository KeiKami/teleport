/*
Copyright 2015-2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentAuth,
})

// InitConfig is auth server init config
type InitConfig struct {
	// Backend is auth backend to use
	Backend backend.Backend

	// Authority is key generator that we use
	Authority sshca.Authority

	// HostUUID is a UUID of this host
	HostUUID string

	// NodeName is the DNS name of the node
	NodeName string

	// ClusterName stores the FQDN of the signing CA (its certificate will have this
	// name embedded). It is usually set to the GUID of the host the Auth service runs on
	ClusterName types.ClusterName

	// Authorities is a list of pre-configured authorities to supply on first start
	Authorities []types.CertAuthority

	// Resources is a list of previously backed-up resources used to
	// bootstrap backend on first start.
	Resources []types.Resource

	// AuthServiceName is a human-readable name of this CA. If several Auth services are running
	// (managing multiple teleport clusters) this field is used to tell them apart in UIs
	// It usually defaults to the hostname of the machine the Auth service runs on.
	AuthServiceName string

	// DataDir is the full path to the directory where keys, events and logs are kept
	DataDir string

	// ReverseTunnels is a list of reverse tunnels statically supplied
	// in configuration, so auth server will init the tunnels on the first start
	ReverseTunnels []types.ReverseTunnel

	// OIDCConnectors is a list of trusted OpenID Connect identity providers
	// in configuration, so auth server will init the tunnels on the first start
	OIDCConnectors []types.OIDCConnector

	// Trust is a service that manages users and credentials
	Trust services.Trust

	// Presence service is a discovery and hearbeat tracker
	Presence services.Presence

	// Provisioner is a service that keeps track of provisioning tokens
	Provisioner services.Provisioner

	// Identity is a service that manages users and credentials
	Identity services.Identity

	// Access is service controlling access to resources
	Access services.Access

	// DynamicAccessExt is a service that manages dynamic RBAC.
	DynamicAccessExt services.DynamicAccessExt

	// Events is an event service
	Events types.Events

	// ClusterConfiguration is a services that holds cluster wide configuration.
	ClusterConfiguration services.ClusterConfiguration

	// Roles is a set of roles to create
	Roles []types.Role

	// StaticTokens are pre-defined host provisioning tokens supplied via config file for
	// environments where paranoid security is not needed
	//StaticTokens []services.ProvisionToken
	StaticTokens types.StaticTokens

	// AuthPreference defines the authentication type (local, oidc) and second
	// factor (off, otp, u2f) passed in from a configuration file.
	AuthPreference types.AuthPreference

	// AuditLog is used for emitting events to audit log.
	AuditLog events.IAuditLog

	// ClusterConfig holds cluster level configuration.
	ClusterConfig types.ClusterConfig

	// ClusterNetworkingConfig holds cluster networking configuration.
	ClusterNetworkingConfig types.ClusterNetworkingConfig

	// SessionRecordingConfig holds session recording configuration.
	SessionRecordingConfig types.SessionRecordingConfig

	// SkipPeriodicOperations turns off periodic operations
	// used in tests that don't need periodc operations.
	SkipPeriodicOperations bool

	// CipherSuites is a list of ciphersuites that the auth server supports.
	CipherSuites []uint16

	// CASigningAlg is a signing algorithm used for SSH (certificate and
	// handshake) signatures for both host and user CAs. This option only
	// affects newly-created CAs.
	CASigningAlg *string

	// Emitter is events emitter, used to submit discrete events
	Emitter apievents.Emitter

	// Streamer is events sessionstreamer, used to create continuous
	// session related streams
	Streamer events.Streamer
}

// Init instantiates and configures an instance of AuthServer
func Init(cfg InitConfig, opts ...ServerOption) (*Server, error) {
	if cfg.DataDir == "" {
		return nil, trace.BadParameter("DataDir: data dir can not be empty")
	}
	if cfg.HostUUID == "" {
		return nil, trace.BadParameter("HostUUID: host UUID can not be empty")
	}

	ctx := context.TODO()

	domainName := cfg.ClusterName.GetClusterName()
	lock, err := backend.AcquireLock(ctx, cfg.Backend, domainName, 30*time.Second)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer lock.Release(ctx, cfg.Backend)

	// check that user CA and host CA are present and set the certs if needed
	asrv, err := NewServer(&cfg, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// if resources are supplied, use them to bootstrap backend state
	// on initial startup.
	if len(cfg.Resources) > 0 {
		firstStart, err := isFirstStart(asrv, cfg)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if firstStart {
			log.Infof("Applying %v bootstrap resources (first initialization)", len(cfg.Resources))
			if err := checkResourceConsistency(domainName, cfg.Resources...); err != nil {
				return nil, trace.Wrap(err, "refusing to bootstrap backend")
			}
			if err := local.CreateResources(ctx, cfg.Backend, cfg.Resources...); err != nil {
				return nil, trace.Wrap(err, "backend bootstrap failed")
			}
		} else {
			log.Warnf("Ignoring %v bootstrap resources (previously initialized)", len(cfg.Resources))
		}
	}

	// Set the ciphersuites that this auth server supports.
	asrv.cipherSuites = cfg.CipherSuites

	// INTERNAL: Authorities (plus Roles) and ReverseTunnels don't follow the
	// same pattern as the rest of the configuration (they are not configuration
	// singletons). However, we need to keep them around while Telekube uses them.
	for _, role := range cfg.Roles {
		if err := asrv.UpsertRole(ctx, role); err != nil {
			return nil, trace.Wrap(err)
		}
		log.Infof("Created role: %v.", role)
	}
	for i := range cfg.Authorities {
		ca := cfg.Authorities[i]
		// Don't re-create CA if it already exists, otherwise
		// the existing cluster configuration will be corrupted;
		// this part of code is only used in tests.
		if err := asrv.Trust.CreateCertAuthority(ca); err != nil {
			if !trace.IsAlreadyExists(err) {
				return nil, trace.Wrap(err)
			}
		} else {
			log.Infof("Created trusted certificate authority: %q, type: %q.", ca.GetName(), ca.GetType())
		}
	}
	for _, tunnel := range cfg.ReverseTunnels {
		if err := asrv.UpsertReverseTunnel(tunnel); err != nil {
			return nil, trace.Wrap(err)
		}
		log.Infof("Created reverse tunnel: %v.", tunnel)
	}

	err = initSetClusterNetworkingConfig(ctx, asrv, cfg.ClusterNetworkingConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = asrv.SetSessionRecordingConfig(ctx, cfg.SessionRecordingConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// set cluster level config on the backend and then force a sync of the cache.
	clusterConfig, err := asrv.GetClusterConfig()
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}
	// init a unique cluster ID, it must be set once only during the first
	// start so if it's already there, reuse it
	if clusterConfig != nil && clusterConfig.GetClusterID() != "" {
		cfg.ClusterConfig.SetClusterID(clusterConfig.GetClusterID())
	} else {
		cfg.ClusterConfig.SetClusterID(uuid.New())
	}
	err = asrv.SetClusterConfig(cfg.ClusterConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// The first Auth Server that starts gets to set the name of the cluster.
	err = asrv.SetClusterName(cfg.ClusterName)
	if err != nil && !trace.IsAlreadyExists(err) {
		return nil, trace.Wrap(err)
	}
	// If the cluster name has already been set, log a warning if the user
	// is trying to change the name.
	if trace.IsAlreadyExists(err) {
		// Get current name of cluster from the backend.
		cn, err := asrv.ClusterConfiguration.GetClusterName()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if cn.GetClusterName() != cfg.ClusterName.GetClusterName() {
			warnMessage := "Cannot rename cluster to %q: continuing with %q. Teleport " +
				"clusters can not be renamed once they are created. You are seeing this " +
				"warning for one of two reasons. Either you have not set \"cluster_name\" in " +
				"Teleport configuration and changed the hostname of the auth server or you " +
				"are trying to change the value of \"cluster_name\"."
			log.Warnf(warnMessage,
				cfg.ClusterName.GetClusterName(),
				cn.GetClusterName())

			// Override user passed in cluster name with what is in the backend.
			cfg.ClusterName = cn
		}
	}
	log.Debugf("Cluster configuration: %v.", cfg.ClusterName)

	err = asrv.SetStaticTokens(cfg.StaticTokens)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.Infof("Updating cluster configuration: %v.", cfg.StaticTokens)

	err = initSetAuthPreference(asrv, cfg.AuthPreference)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// always create the default namespace
	err = asrv.UpsertNamespace(types.NewNamespace(defaults.Namespace))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.Infof("Created namespace: %q.", defaults.Namespace)

	// always create a default admin role
	defaultRole := services.NewAdminRole()
	err = asrv.CreateRole(defaultRole)
	if err != nil && !trace.IsAlreadyExists(err) {
		return nil, trace.Wrap(err)
	}
	if !trace.IsAlreadyExists(err) {
		log.Infof("Created default admin role: %q.", defaultRole.GetName())
	}

	// generate a user certificate authority if it doesn't exist
	userCA, err := asrv.GetCertAuthority(types.CertAuthID{DomainName: cfg.ClusterName.GetClusterName(), Type: types.UserCA}, true)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}

		log.Infof("First start: generating user certificate authority.")
		priv, pub, err := asrv.GenerateKeyPair("")
		if err != nil {
			return nil, trace.Wrap(err)
		}

		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
			CommonName:   cfg.ClusterName.GetClusterName(),
			Organization: []string{cfg.ClusterName.GetClusterName()},
		}, nil, defaults.CATTL)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		sigAlg := defaults.CASignatureAlgorithm
		if cfg.CASigningAlg != nil && *cfg.CASigningAlg != "" {
			sigAlg = *cfg.CASigningAlg
		}

		userCA := &types.CertAuthorityV2{
			Kind:    types.KindCertAuthority,
			Version: types.V2,
			Metadata: types.Metadata{
				Name:      cfg.ClusterName.GetClusterName(),
				Namespace: defaults.Namespace,
			},
			Spec: types.CertAuthoritySpecV2{
				ClusterName:  cfg.ClusterName.GetClusterName(),
				Type:         types.UserCA,
				SigningKeys:  [][]byte{priv},
				SigningAlg:   sshutils.ParseSigningAlg(sigAlg),
				CheckingKeys: [][]byte{pub},
				TLSKeyPairs:  []types.TLSKeyPair{{Cert: certPEM, Key: keyPEM}},
			},
		}

		if err := asrv.Trust.UpsertCertAuthority(userCA); err != nil {
			return nil, trace.Wrap(err)
		}
	} else if len(userCA.GetTLSKeyPairs()) == 0 {
		log.Infof("Migrate: generating TLS CA for existing user CA.")
		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
			CommonName:   cfg.ClusterName.GetClusterName(),
			Organization: []string{cfg.ClusterName.GetClusterName()},
		}, nil, defaults.CATTL)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		userCA.SetTLSKeyPairs([]types.TLSKeyPair{{Cert: certPEM, Key: keyPEM}})
		if err := asrv.Trust.UpsertCertAuthority(userCA); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// generate a host certificate authority if it doesn't exist
	hostCA, err := asrv.GetCertAuthority(types.CertAuthID{DomainName: cfg.ClusterName.GetClusterName(), Type: types.HostCA}, true)
	if err != nil {
		if !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}

		log.Infof("First start: generating host certificate authority.")
		priv, pub, err := asrv.GenerateKeyPair("")
		if err != nil {
			return nil, trace.Wrap(err)
		}

		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
			CommonName:   cfg.ClusterName.GetClusterName(),
			Organization: []string{cfg.ClusterName.GetClusterName()},
		}, nil, defaults.CATTL)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		sigAlg := defaults.CASignatureAlgorithm
		if cfg.CASigningAlg != nil && *cfg.CASigningAlg != "" {
			sigAlg = *cfg.CASigningAlg
		}

		hostCA = &types.CertAuthorityV2{
			Kind:    types.KindCertAuthority,
			Version: types.V2,
			Metadata: types.Metadata{
				Name:      cfg.ClusterName.GetClusterName(),
				Namespace: defaults.Namespace,
			},
			Spec: types.CertAuthoritySpecV2{
				ClusterName:  cfg.ClusterName.GetClusterName(),
				Type:         types.HostCA,
				SigningKeys:  [][]byte{priv},
				SigningAlg:   sshutils.ParseSigningAlg(sigAlg),
				CheckingKeys: [][]byte{pub},
				TLSKeyPairs:  []types.TLSKeyPair{{Cert: certPEM, Key: keyPEM}},
			},
		}
		if err := asrv.Trust.UpsertCertAuthority(hostCA); err != nil {
			return nil, trace.Wrap(err)
		}
	} else if len(hostCA.GetTLSKeyPairs()) == 0 {
		log.Infof("Migrate: generating TLS CA for existing host CA.")
		privateKey, err := ssh.ParseRawPrivateKey(hostCA.GetSigningKeys()[0])
		if err != nil {
			return nil, trace.Wrap(err)
		}
		privateKeyRSA, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, trace.BadParameter("expected RSA private key, got %T", privateKey)
		}
		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCAWithPrivateKey(privateKeyRSA, pkix.Name{
			CommonName:   cfg.ClusterName.GetClusterName(),
			Organization: []string{cfg.ClusterName.GetClusterName()},
		}, nil, defaults.CATTL)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		hostCA.SetTLSKeyPairs([]types.TLSKeyPair{{Cert: certPEM, Key: keyPEM}})
		if err := asrv.Trust.UpsertCertAuthority(hostCA); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// If a JWT signer does not exist for this cluster, create one.
	jwtSigner, err := asrv.GetCertAuthority(types.CertAuthID{
		DomainName: cfg.ClusterName.GetClusterName(),
		Type:       types.JWTSigner,
	}, true)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}
	if trace.IsNotFound(err) || len(jwtSigner.GetJWTKeyPairs()) == 0 {
		log.Infof("Migrate: Adding JWT key to existing cluster %q.", cfg.ClusterName.GetClusterName())

		jwtSigner, err = services.NewJWTAuthority(cfg.ClusterName.GetClusterName())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if err := asrv.Trust.UpsertCertAuthority(jwtSigner); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	if lib.IsInsecureDevMode() {
		warningMessage := "Starting teleport in insecure mode. This is " +
			"dangerous! Sensitive information will be logged to console and " +
			"certificates will not be verified. Proceed with caution!"
		log.Warn(warningMessage)
	}

	// Migrate any legacy resources to new format.
	err = migrateLegacyResources(ctx, cfg, asrv)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create presets - convenience and example resources.
	err = createPresets(ctx, asrv)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !cfg.SkipPeriodicOperations {
		log.Infof("Auth server is running periodic operations.")
		go asrv.runPeriodicOperations()
	} else {
		log.Infof("Auth server is skipping periodic operations.")
	}

	return asrv, nil
}

func initSetAuthPreference(asrv *Server, newAuthPref types.AuthPreference) error {
	storedAuthPref, err := asrv.GetAuthPreference()
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	shouldReplace, err := shouldInitReplaceResourceWithOrigin(storedAuthPref, newAuthPref)
	if err != nil {
		return trace.Wrap(err)
	}
	if shouldReplace {
		if err := asrv.SetAuthPreference(newAuthPref); err != nil {
			return trace.Wrap(err)
		}
		log.Infof("Updating cluster auth preference: %v.", newAuthPref)
	}
	return nil
}

func initSetClusterNetworkingConfig(ctx context.Context, asrv *Server, newNetConfig types.ClusterNetworkingConfig) error {
	storedNetConfig, err := asrv.GetClusterNetworkingConfig(ctx)
	if err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
	}
	shouldReplace, err := shouldInitReplaceResourceWithOrigin(storedNetConfig, newNetConfig)
	if err != nil {
		return trace.Wrap(err)
	}
	if shouldReplace {
		if err := asrv.SetClusterNetworkingConfig(ctx, newNetConfig); err != nil {
			return trace.Wrap(err)
		}
		log.Infof("Updating cluster networking configuration: %v.", newNetConfig)
	}
	return nil
}

// shouldInitReplaceResourceWithOrigin determines whether the candidate
// resource should be used to replace the stored resource during auth server
// initialization.  Dynamically configured resources must not be overwritten
// when the corresponding file config is left unspecified (i.e., by defaults).
func shouldInitReplaceResourceWithOrigin(stored, candidate types.ResourceWithOrigin) (bool, error) {
	if candidate == nil || (candidate.Origin() != types.OriginDefaults && candidate.Origin() != types.OriginConfigFile) {
		return false, trace.BadParameter("candidate origin must be either defaults or config-file (this is a bug)")
	}

	// If there is no resource stored in the backend or it was not dynamically
	// configured, the candidate resource should be stored in the backend.
	if stored == nil || stored.Origin() != types.OriginDynamic {
		return true, nil
	}

	// If the candidate resource is explicitly configured in the config file,
	// store this config-file resource in the backend no matter what.
	if candidate.Origin() == types.OriginConfigFile {
		// Log a warning when about to overwrite a dynamically configured resource.
		if stored.Origin() == types.OriginDynamic {
			log.Warnf("Stored %v resource that was configured dynamically is about to be discarded in favor of explicit file configuration.", stored.GetKind())
		}
		return true, nil
	}

	// The resource in the backend was configured dynamically, and there is no
	// more authoritative file configuration to replace it.  Keep the stored
	// dynamic resource.
	return false, nil
}

func migrateLegacyResources(ctx context.Context, cfg InitConfig, asrv *Server) error {
	err := migrateOSS(ctx, asrv)
	if err != nil {
		return trace.Wrap(err)
	}

	err = migrateRemoteClusters(ctx, asrv)
	if err != nil {
		return trace.Wrap(err)
	}

	err = migrateRoleOptions(ctx, asrv)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := migrateMFADevices(ctx, asrv); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// createPresets creates preset resources - roles
func createPresets(ctx context.Context, asrv *Server) error {
	roles := []types.Role{
		services.NewPresetEditorRole(),
		services.NewPresetAccessRole(),
		services.NewPresetAuditorRole()}
	for _, role := range roles {
		err := asrv.CreateRole(role)
		if err != nil {
			if !trace.IsAlreadyExists(err) {
				return trace.Wrap(err, "failed to create preset role")
			}
		}
	}
	return nil
}

const migrationAbortedMessage = "migration to RBAC has aborted because of the backend error, restart teleport to try again"

// migrateOSS performs migration to enable role-based access controls
// to open source users. It creates a less privileged role 'ossuser'
// and migrates all users and trusted cluster mappings to it
// this function can be called multiple times
// DELETE IN(7.0)
func migrateOSS(ctx context.Context, asrv *Server) error {
	if modules.GetModules().BuildType() != modules.BuildOSS {
		return nil
	}
	role := services.NewDowngradedOSSAdminRole()
	existing, err := asrv.GetRole(ctx, role.GetName())
	if err != nil {
		return trace.Wrap(err, "expected to find built-in admin role")
	}
	_, ok := existing.GetMetadata().Labels[teleport.OSSMigratedV6]
	if ok {
		log.Debugf("Admin role is already migrated, skipping OSS migration.")
		// Role is created, assume that migration has been completed.
		// To re-run the migration, users can remove migrated label from the role
		return nil
	}
	err = asrv.UpsertRole(ctx, role)
	updatedRoles := 0
	if err != nil {
		return trace.Wrap(err, migrationAbortedMessage)
	}
	if err == nil {
		updatedRoles++
		log.Infof("Enabling RBAC in OSS Teleport. Migrating users, roles and trusted clusters.")
	}
	migratedUsers, err := migrateOSSUsers(ctx, role, asrv)
	if err != nil {
		return trace.Wrap(err, migrationAbortedMessage)
	}

	migratedTcs, err := migrateOSSTrustedClusters(ctx, role, asrv)
	if err != nil {
		return trace.Wrap(err, migrationAbortedMessage)
	}

	migratedConns, err := migrateOSSGithubConns(ctx, role, asrv)
	if err != nil {
		return trace.Wrap(err, migrationAbortedMessage)
	}

	if updatedRoles > 0 || migratedUsers > 0 || migratedTcs > 0 || migratedConns > 0 {
		log.Infof("Migration completed. Created %v roles, updated %v users, %v trusted clusters and %v Github connectors.",
			updatedRoles, migratedUsers, migratedTcs, migratedConns)
	}

	return nil
}

// migrateOSSTrustedClusters updates role mappings in trusted clusters
// OSS Trusted clusters had no explicit mapping from remote roles, to local roles.
// Maps admin roles to local OSS admin role.
func migrateOSSTrustedClusters(ctx context.Context, role types.Role, asrv *Server) (int, error) {
	migratedTcs := 0
	tcs, err := asrv.GetTrustedClusters(ctx)
	if err != nil {
		return migratedTcs, trace.Wrap(err, migrationAbortedMessage)
	}

	for _, tc := range tcs {
		meta := tc.GetMetadata()
		_, ok := meta.Labels[teleport.OSSMigratedV6]
		if ok {
			continue
		}
		setLabels(&meta.Labels, teleport.OSSMigratedV6, types.True)
		roleMap := []types.RoleMapping{{Remote: role.GetName(), Local: []string{role.GetName()}}}
		tc.SetRoleMap(roleMap)
		tc.SetMetadata(meta)
		if _, err := asrv.Presence.UpsertTrustedCluster(ctx, tc); err != nil {
			return migratedTcs, trace.Wrap(err, migrationAbortedMessage)
		}
		for _, catype := range []types.CertAuthType{types.UserCA, types.HostCA} {
			ca, err := asrv.GetCertAuthority(types.CertAuthID{Type: catype, DomainName: tc.GetName()}, true)
			if err != nil {
				return migratedTcs, trace.Wrap(err, migrationAbortedMessage)
			}
			meta := ca.GetMetadata()
			_, ok := meta.Labels[teleport.OSSMigratedV6]
			if ok {
				continue
			}
			setLabels(&meta.Labels, teleport.OSSMigratedV6, types.True)
			ca.SetRoleMap(roleMap)
			ca.SetMetadata(meta)
			err = asrv.UpsertCertAuthority(ca)
			if err != nil {
				return migratedTcs, trace.Wrap(err, migrationAbortedMessage)
			}
		}
		migratedTcs++
	}
	return migratedTcs, nil
}

// migrateOSSUsers assigns all OSS users to a less privileged role
// All OSS users were using implicit admin role. Migrate all users to less privileged
// role that is read only and only lets users use assigned logins.
func migrateOSSUsers(ctx context.Context, role types.Role, asrv *Server) (int, error) {
	migratedUsers := 0
	users, err := asrv.GetUsers(true)
	if err != nil {
		return migratedUsers, trace.Wrap(err, migrationAbortedMessage)
	}

	for _, user := range users {
		meta := user.GetMetadata()
		_, ok := meta.Labels[teleport.OSSMigratedV6]
		if ok {
			continue
		}
		setLabels(&meta.Labels, teleport.OSSMigratedV6, types.True)
		user.SetRoles([]string{role.GetName()})
		user.SetMetadata(meta)
		if err := asrv.UpsertUser(user); err != nil {
			return migratedUsers, trace.Wrap(err, migrationAbortedMessage)
		}
		migratedUsers++
	}

	return migratedUsers, nil
}

func setLabels(v *map[string]string, key, val string) {
	if *v == nil {
		*v = map[string]string{
			key: val,
		}
		return
	}
	(*v)[key] = val
}

func migrateOSSGithubConns(ctx context.Context, role types.Role, asrv *Server) (int, error) {
	migratedConns := 0
	// Migrate Github's OSS teams_to_logins to teams_to_roles.
	// To do that, create a new role per connector's teams_to_logins entry
	conns, err := asrv.GetGithubConnectors(ctx, true)
	if err != nil {
		return migratedConns, trace.Wrap(err)
	}
	for _, conn := range conns {
		meta := conn.GetMetadata()
		_, ok := meta.Labels[teleport.OSSMigratedV6]
		if ok {
			continue
		}
		setLabels(&meta.Labels, teleport.OSSMigratedV6, types.True)
		conn.SetMetadata(meta)
		// replace every team with a new role
		teams := conn.GetTeamsToLogins()
		newTeams := make([]types.TeamMapping, len(teams))
		for i, team := range teams {
			r := services.NewOSSGithubRole(team.Logins, team.KubeUsers, team.KubeGroups)
			err := asrv.CreateRole(r)
			if err != nil {
				return migratedConns, trace.Wrap(err)
			}
			newTeams[i] = types.TeamMapping{
				Organization: team.Organization,
				Team:         team.Team,
				Logins:       []string{r.GetName()},
			}
		}
		conn.SetTeamsToLogins(newTeams)
		if err := asrv.UpsertGithubConnector(ctx, conn); err != nil {
			return migratedConns, trace.Wrap(err)
		}
		migratedConns++
	}

	return migratedConns, nil
}

// isFirstStart returns 'true' if the auth server is starting for the 1st time
// on this server.
func isFirstStart(authServer *Server, cfg InitConfig) (bool, error) {
	// check if the CA exists?
	_, err := authServer.GetCertAuthority(
		types.CertAuthID{
			DomainName: cfg.ClusterName.GetClusterName(),
			Type:       types.HostCA,
		}, false)
	if err != nil {
		if !trace.IsNotFound(err) {
			return false, trace.Wrap(err)
		}
		// If a CA was not found, that means this is the first start.
		return true, nil
	}
	return false, nil
}

// checkResourceConsistency checks far basic conflicting state issues.
func checkResourceConsistency(clusterName string, resources ...types.Resource) error {
	for _, rsc := range resources {
		switch r := rsc.(type) {
		case types.CertAuthority:
			// check that signing CAs have expected cluster name and that
			// all CAs for this cluster do having signing keys.
			seemsLocal := r.GetClusterName() == clusterName
			var hasKeys bool
			_, err := r.FirstSigningKey()
			switch {
			case err == nil:
				hasKeys = true
			case trace.IsNotFound(err):
				hasKeys = false
			default:
				return trace.Wrap(err)
			}
			if seemsLocal && !hasKeys {
				return trace.BadParameter("ca for local cluster %q missing signing keys", clusterName)
			}
			if !seemsLocal && hasKeys {
				return trace.BadParameter("unexpected cluster name %q for signing ca (expected %q)", r.GetClusterName(), clusterName)
			}
		case types.TrustedCluster:
			if r.GetName() == clusterName {
				return trace.BadParameter("trusted cluster has same name as local cluster (%q)", clusterName)
			}
		default:
			// No validation checks for this resource type
		}
	}
	return nil
}

// GenerateIdentity generates identity for the auth server
func GenerateIdentity(a *Server, id IdentityID, additionalPrincipals, dnsNames []string) (*Identity, error) {
	keys, err := a.GenerateServerKeys(GenerateServerKeysRequest{
		HostID:               id.HostUUID,
		NodeName:             id.NodeName,
		Roles:                types.SystemRoles{id.Role},
		AdditionalPrincipals: additionalPrincipals,
		DNSNames:             dnsNames,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ReadIdentityFromKeyPair(keys)
}

// Identity is collection of certificates and signers that represent server identity
type Identity struct {
	// ID specifies server unique ID, name and role
	ID IdentityID
	// KeyBytes is a PEM encoded private key
	KeyBytes []byte
	// CertBytes is a PEM encoded SSH host cert
	CertBytes []byte
	// TLSCertBytes is a PEM encoded TLS x509 client certificate
	TLSCertBytes []byte
	// TLSCACertBytes is a list of PEM encoded TLS x509 certificate of certificate authority
	// associated with auth server services
	TLSCACertsBytes [][]byte
	// SSHCACertBytes is a list of SSH CAs encoded in the authorized_keys format.
	SSHCACertBytes [][]byte
	// KeySigner is an SSH host certificate signer
	KeySigner ssh.Signer
	// Cert is a parsed SSH certificate
	Cert *ssh.Certificate
	// XCert is X509 client certificate
	XCert *x509.Certificate
	// ClusterName is a name of host's cluster
	ClusterName string
}

// String returns user-friendly representation of the identity.
func (i *Identity) String() string {
	var out []string
	if i.XCert != nil {
		out = append(out, fmt.Sprintf("cert(%v issued by %v:%v)", i.XCert.Subject.CommonName, i.XCert.Issuer.CommonName, i.XCert.Issuer.SerialNumber))
	}
	for j := range i.TLSCACertsBytes {
		cert, err := tlsca.ParseCertificatePEM(i.TLSCACertsBytes[j])
		if err != nil {
			out = append(out, err.Error())
		} else {
			out = append(out, fmt.Sprintf("trust root(%v:%v)", cert.Subject.CommonName, cert.Subject.SerialNumber))
		}
	}
	return fmt.Sprintf("Identity(%v, %v)", i.ID.Role, strings.Join(out, ","))
}

// CertInfo returns diagnostic information about certificate
func CertInfo(cert *x509.Certificate) string {
	return fmt.Sprintf("cert(%v issued by %v:%v)", cert.Subject.CommonName, cert.Issuer.CommonName, cert.Issuer.SerialNumber)
}

// TLSCertInfo returns diagnostic information about certificate
func TLSCertInfo(cert *tls.Certificate) string {
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err.Error()
	}
	return CertInfo(x509cert)
}

// CertAuthorityInfo returns debugging information about certificate authority
func CertAuthorityInfo(ca types.CertAuthority) string {
	var out []string
	for _, keyPair := range ca.GetTLSKeyPairs() {
		cert, err := tlsca.ParseCertificatePEM(keyPair.Cert)
		if err != nil {
			out = append(out, err.Error())
		} else {
			out = append(out, fmt.Sprintf("trust root(%v:%v)", cert.Subject.CommonName, cert.Subject.SerialNumber))
		}
	}
	return fmt.Sprintf("cert authority(state: %v, phase: %v, roots: %v)", ca.GetRotation().State, ca.GetRotation().Phase, strings.Join(out, ", "))
}

// HasTSLConfig returns true if this identity has TLS certificate and private key
func (i *Identity) HasTLSConfig() bool {
	return len(i.TLSCACertsBytes) != 0 && len(i.TLSCertBytes) != 0
}

// HasPrincipals returns whether identity has principals
func (i *Identity) HasPrincipals(additionalPrincipals []string) bool {
	set := utils.StringsSet(i.Cert.ValidPrincipals)
	for _, principal := range additionalPrincipals {
		if _, ok := set[principal]; !ok {
			return false
		}
	}
	return true
}

// HasDNSNames returns true if TLS certificate has required DNS names
func (i *Identity) HasDNSNames(dnsNames []string) bool {
	if i.XCert == nil {
		return false
	}
	set := utils.StringsSet(i.XCert.DNSNames)
	for _, dnsName := range dnsNames {
		if _, ok := set[dnsName]; !ok {
			return false
		}
	}
	return true
}

// TLSConfig returns TLS config for mutual TLS authentication
// can return NotFound error if there are no TLS credentials setup for identity
func (i *Identity) TLSConfig(cipherSuites []uint16) (*tls.Config, error) {
	tlsConfig := utils.TLSConfig(cipherSuites)
	if !i.HasTLSConfig() {
		return nil, trace.NotFound("no TLS credentials setup for this identity")
	}
	tlsCert, err := tls.X509KeyPair(i.TLSCertBytes, i.KeyBytes)
	if err != nil {
		return nil, trace.BadParameter("failed to parse private key: %v", err)
	}
	certPool := x509.NewCertPool()
	for j := range i.TLSCACertsBytes {
		parsedCert, err := tlsca.ParseCertificatePEM(i.TLSCACertsBytes[j])
		if err != nil {
			return nil, trace.Wrap(err, "failed to parse CA certificate")
		}
		certPool.AddCert(parsedCert)
	}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.RootCAs = certPool
	tlsConfig.ClientCAs = certPool
	tlsConfig.ServerName = EncodeClusterName(i.ClusterName)
	return tlsConfig, nil
}

// SSHClientConfig returns a ssh.ClientConfig used by nodes to connect to
// the reverse tunnel server.
func (i *Identity) SSHClientConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: i.ID.HostUUID,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(i.KeySigner),
		},
		HostKeyCallback: i.hostKeyCallback,
		Timeout:         defaults.DefaultDialTimeout,
	}
}

// hostKeyCallback checks if the host certificate was signed by any of the
// known CAs.
func (i *Identity) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return trace.BadParameter("only host certificates supported")
	}

	// Loop over all CAs and see if any of them signed the certificate.
	for _, k := range i.SSHCACertBytes {
		pubkey, _, _, _, err := ssh.ParseAuthorizedKey(k)
		if err != nil {
			return trace.Wrap(err)
		}
		if apisshutils.KeysEqual(cert.SignatureKey, pubkey) {
			return nil
		}
	}

	return trace.BadParameter("no matching keys found")
}

// IdentityID is a combination of role, host UUID, and node name.
type IdentityID struct {
	Role     types.SystemRole
	HostUUID string
	NodeName string
}

// HostID is host ID part of the host UUID that consists cluster name
func (id *IdentityID) HostID() (string, error) {
	parts := strings.Split(id.HostUUID, ".")
	if len(parts) < 2 {
		return "", trace.BadParameter("expected 2 parts in %q", id.HostUUID)
	}
	return parts[0], nil
}

// Equals returns true if two identities are equal
func (id *IdentityID) Equals(other IdentityID) bool {
	return id.Role == other.Role && id.HostUUID == other.HostUUID
}

// String returns debug friendly representation of this identity
func (id *IdentityID) String() string {
	return fmt.Sprintf("Identity(hostuuid=%v, role=%v)", id.HostUUID, id.Role)
}

// ReadIdentityFromKeyPair reads SSH and TLS identity from key pair.
func ReadIdentityFromKeyPair(keys *PackedKeys) (*Identity, error) {
	identity, err := ReadSSHIdentityFromKeyPair(keys.Key, keys.Cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(keys.SSHCACerts) != 0 {
		identity.SSHCACertBytes = keys.SSHCACerts
	}

	if len(keys.TLSCACerts) != 0 {
		// Parse the key pair to verify that identity parses properly for future use.
		i, err := ReadTLSIdentityFromKeyPair(keys.Key, keys.TLSCert, keys.TLSCACerts)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		identity.XCert = i.XCert
		identity.TLSCertBytes = keys.TLSCert
		identity.TLSCACertsBytes = keys.TLSCACerts
	}

	return identity, nil
}

// ReadTLSIdentityFromKeyPair reads TLS identity from key pair
func ReadTLSIdentityFromKeyPair(keyBytes, certBytes []byte, caCertsBytes [][]byte) (*Identity, error) {
	if len(keyBytes) == 0 {
		return nil, trace.BadParameter("missing private key")
	}

	if len(certBytes) == 0 {
		return nil, trace.BadParameter("missing certificate")
	}

	cert, err := tlsca.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse TLS certificate")
	}

	id, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(cert.Issuer.Organization) == 0 {
		return nil, trace.BadParameter("missing CA organization")
	}

	clusterName := cert.Issuer.Organization[0]
	if clusterName == "" {
		return nil, trace.BadParameter("misssing cluster name")
	}
	identity := &Identity{
		ID:              IdentityID{HostUUID: id.Username, Role: types.SystemRole(id.Groups[0])},
		ClusterName:     clusterName,
		KeyBytes:        keyBytes,
		TLSCertBytes:    certBytes,
		TLSCACertsBytes: caCertsBytes,
		XCert:           cert,
	}
	// The passed in ciphersuites don't appear to matter here since the returned
	// *tls.Config is never actually used?
	_, err = identity.TLSConfig(utils.DefaultCipherSuites())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return identity, nil
}

// ReadSSHIdentityFromKeyPair reads identity from initialized keypair
func ReadSSHIdentityFromKeyPair(keyBytes, certBytes []byte) (*Identity, error) {
	if len(keyBytes) == 0 {
		return nil, trace.BadParameter("PrivateKey: missing private key")
	}

	if len(certBytes) == 0 {
		return nil, trace.BadParameter("Cert: missing parameter")
	}

	cert, err := apisshutils.ParseCertificate(certBytes)
	if err != nil {
		return nil, trace.BadParameter("failed to parse server certificate: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, trace.BadParameter("failed to parse private key: %v", err)
	}
	// this signer authenticates using certificate signed by the cert authority
	// not only by the public key
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, trace.BadParameter("unsupported private key: %v", err)
	}

	// check principals on certificate
	if len(cert.ValidPrincipals) < 1 {
		return nil, trace.BadParameter("valid principals: at least one valid principal is required")
	}
	for _, validPrincipal := range cert.ValidPrincipals {
		if validPrincipal == "" {
			return nil, trace.BadParameter("valid principal can not be empty: %q", cert.ValidPrincipals)
		}
	}

	// check permissions on certificate
	if len(cert.Permissions.Extensions) == 0 {
		return nil, trace.BadParameter("extensions: misssing needed extensions for host roles")
	}
	roleString := cert.Permissions.Extensions[utils.CertExtensionRole]
	if roleString == "" {
		return nil, trace.BadParameter("misssing cert extension %v", utils.CertExtensionRole)
	}
	roles, err := types.ParseTeleportRoles(roleString)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	foundRoles := len(roles)
	if foundRoles != 1 {
		return nil, trace.Errorf("expected one role per certificate. found %d: '%s'",
			foundRoles, roles.String())
	}
	role := roles[0]
	clusterName := cert.Permissions.Extensions[utils.CertExtensionAuthority]
	if clusterName == "" {
		return nil, trace.BadParameter("missing cert extension %v", utils.CertExtensionAuthority)
	}

	return &Identity{
		ID:          IdentityID{HostUUID: cert.ValidPrincipals[0], Role: role},
		ClusterName: clusterName,
		KeyBytes:    keyBytes,
		CertBytes:   certBytes,
		KeySigner:   certSigner,
		Cert:        cert,
	}, nil
}

// ReadLocalIdentity reads, parses and returns the given pub/pri key + cert from the
// key storage (dataDir).
func ReadLocalIdentity(dataDir string, id IdentityID) (*Identity, error) {
	storage, err := NewProcessStorage(context.TODO(), dataDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer storage.Close()
	return storage.ReadIdentity(IdentityCurrent, id.Role)
}

// DELETE IN: 2.7.0
// NOTE: Sadly, our integration tests depend on this logic
// because they create remote cluster resource. Our integration
// tests should be migrated to use trusted clusters instead of manually
// creating tunnels.
// This migration adds remote cluster resource migrating from 2.5.0
// where the presence of remote cluster was identified only by presence
// of host certificate authority with cluster name not equal local cluster name
func migrateRemoteClusters(ctx context.Context, asrv *Server) error {
	clusterName, err := asrv.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}
	certAuthorities, err := asrv.GetCertAuthorities(types.HostCA, false)
	if err != nil {
		return trace.Wrap(err)
	}
	// loop over all roles and make sure any v3 roles have permit port
	// forward and forward agent allowed
	for _, certAuthority := range certAuthorities {
		if certAuthority.GetName() == clusterName.GetClusterName() {
			log.Debugf("Migrations: skipping local cluster cert authority %q.", certAuthority.GetName())
			continue
		}
		// remote cluster already exists
		_, err = asrv.GetRemoteCluster(certAuthority.GetName())
		if err == nil {
			log.Debugf("Migrations: remote cluster already exists for cert authority %q.", certAuthority.GetName())
			continue
		}
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		// the cert authority is associated with trusted cluster
		_, err = asrv.GetTrustedCluster(ctx, certAuthority.GetName())
		if err == nil {
			log.Debugf("Migrations: trusted cluster resource exists for cert authority %q.", certAuthority.GetName())
			continue
		}
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		remoteCluster, err := types.NewRemoteCluster(certAuthority.GetName())
		if err != nil {
			return trace.Wrap(err)
		}
		err = asrv.CreateRemoteCluster(remoteCluster)
		if err != nil {
			if !trace.IsAlreadyExists(err) {
				return trace.Wrap(err)
			}
		}
		log.Infof("Migrations: added remote cluster resource for cert authority %q.", certAuthority.GetName())
	}

	return nil
}

// DELETE IN: 4.3.0.
// migrateRoleOptions adds the "enhanced_recording" option to all roles.
func migrateRoleOptions(ctx context.Context, asrv *Server) error {
	roles, err := asrv.GetRoles(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, role := range roles {
		options := role.GetOptions()
		if options.BPF == nil {
			log.Debugf("Migrating role %v. Added default enhanced events.", role.GetName())
			options.BPF = defaults.EnhancedEvents()
		} else {
			continue
		}
		role.SetOptions(options)
		err := asrv.UpsertRole(ctx, role)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// DELETE IN: 7.0.0
// migrateMFADevices migrates registered MFA devices to the new storage format.
func migrateMFADevices(ctx context.Context, asrv *Server) error {
	users, err := asrv.GetUsers(true)
	if err != nil {
		return trace.Wrap(err)
	}

	for _, user := range users {
		la := user.GetLocalAuth()
		if la == nil {
			continue
		}
		if len(la.MFA) > 0 {
			// User already migrated.
			continue
		}

		if len(la.TOTPKey) > 0 {
			d, err := services.NewTOTPDevice("totp", la.TOTPKey, asrv.clock.Now())
			if err != nil {
				return trace.Wrap(err)
			}
			la.MFA = append(la.MFA, d)

			la.TOTPKey = ""
		}
		if la.U2FRegistration != nil {
			pubKeyI, err := x509.ParsePKIXPublicKey(la.U2FRegistration.PubKey)
			if err != nil {
				return trace.Wrap(err)
			}
			pubKey, ok := pubKeyI.(*ecdsa.PublicKey)
			if !ok {
				return trace.BadParameter("expected *ecdsa.PublicKey, got %T", pubKeyI)
			}
			d, err := u2f.NewDevice("u2f", &u2f.Registration{
				KeyHandle: la.U2FRegistration.KeyHandle,
				PubKey:    *pubKey,
			}, asrv.clock.Now())
			if err != nil {
				return trace.Wrap(err)
			}
			d.GetU2F().Counter = la.U2FCounter
			la.MFA = append(la.MFA, d)

			la.U2FRegistration = nil
			la.U2FCounter = 0
		}

		if len(la.MFA) == 0 {
			// No MFA devices to migrate.
			continue
		}

		log.Debugf("Migrating MFA devices in LocalAuth for user %q", user.GetName())
		user.SetLocalAuth(la)
		if err := asrv.UpsertUser(user); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}
