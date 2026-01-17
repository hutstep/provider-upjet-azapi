// SPDX-FileCopyrightText: 2025 Upbound Inc. <https://upbound.io>
//
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Azure/terraform-provider-azapi/xpprovider"
	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/crossplane/upjet/v2/pkg/terraform"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clusterv1beta1 "github.com/upbound/provider-azapi/v2/apis/cluster/v1beta1"
	namespacedv1beta1 "github.com/upbound/provider-azapi/v2/apis/namespaced/v1beta1"
)

const (
	// error messages
	errNoProviderConfig     = "no providerConfigRef provided"
	errGetProviderConfig    = "cannot get referenced ProviderConfig"
	errTrackUsage           = "cannot track ProviderConfig usage"
	errExtractCredentials   = "cannot extract credentials"
	errUnmarshalCredentials = "cannot unmarshal azapi credentials as JSON"
	errTenantIDNotSet       = "tenant ID must be set in ProviderConfig when credential source is InjectedIdentity, UserAssignedManagedIdentity, SystemAssignedManagedIdentity, or OIDCTokenFile"
	errClientIDNotSet       = "client ID must be set in ProviderConfig when credential source is OIDCTokenFile"
	errSubscriptionIDNotSet = "subscription ID must be set in ProviderConfig when credential source is InjectedIdentity, UserAssignedManagedIdentity, SystemAssignedManagedIdentity, or OIDCTokenFile"
	// Azure service principal credentials file JSON keys
	keyAzureSubscriptionID = "subscriptionId"
	keyAzureClientID       = "clientId"
	keyAzureClientSecret   = "clientSecret"
	keyAzureTenantID       = "tenantId"
	// Terraform Provider configuration block keys
	keySubscriptionID    = "subscription_id"
	keyClientID          = "client_id"
	keyTenantID          = "tenant_id"
	keyClientSecret      = "client_secret"
	keyEnvironment       = "environment"
	keyUseMSI            = "use_msi"
	keyUseOIDC           = "use_oidc"
	keyOIDCTokenFilePath = "oidc_token_file_path"
	keyUseAKSWorkloadID  = "use_aks_workload_identity"
	// Default OidcTokenFilePath
	defaultOidcTokenFilePath = "/var/run/secrets/azure/tokens/azure-identity-token"
)

var (
	credentialsSourceUserAssignedManagedIdentity   xpv1.CredentialsSource = "UserAssignedManagedIdentity"
	credentialsSourceSystemAssignedManagedIdentity xpv1.CredentialsSource = "SystemAssignedManagedIdentity"
	credentialsSourceOIDCTokenFile                 xpv1.CredentialsSource = "OIDCTokenFile"
)

// TerraformSetupBuilder returns Terraform setup with provider specific
// configuration like provider credentials used to connect to cloud APIs in the
// expected form of a Terraform provider.
func TerraformSetupBuilder() terraform.SetupFn { //nolint:gocyclo
	return func(ctx context.Context, crClient client.Client, mgx resource.Managed) (terraform.Setup, error) {
		ps := terraform.Setup{}

		pcSpec, err := resolveProviderConfig(ctx, crClient, mgx)
		if err != nil {
			return terraform.Setup{}, err
		}

		ps.Configuration = map[string]any{}

		switch pcSpec.Credentials.Source { //nolint:exhaustive
		case credentialsSourceSystemAssignedManagedIdentity, credentialsSourceUserAssignedManagedIdentity:
			err = msiAuth(pcSpec, &ps)
		case credentialsSourceOIDCTokenFile:
			err = oidcAuth(pcSpec, &ps)
		default:
			err = spAuth(ctx, pcSpec, &ps, crClient)
		}
		if err != nil {
			return terraform.Setup{}, errors.Wrap(err, "failed to prepare terraform.Setup")
		}

		ps.FrameworkProvider, err = xpprovider.FrameworkProvider(ctx)
		if err != nil {
			return terraform.Setup{}, errors.Wrap(err, "error initializing the framework provider")
		}
		return ps, nil
	}
}

// spAuth configures service principal authentication (using client secret from credentials)
func spAuth(ctx context.Context, pcSpec *namespacedv1beta1.ProviderConfigSpec, ps *terraform.Setup, crClient client.Client) error {
	data, err := resource.CommonCredentialExtractor(ctx, pcSpec.Credentials.Source, crClient, pcSpec.Credentials.CommonCredentialSelectors)
	if err != nil {
		return errors.Wrap(err, errExtractCredentials)
	}
	data = []byte(strings.TrimSpace(string(data)))
	azureCreds := map[string]string{}
	if err := json.Unmarshal(data, &azureCreds); err != nil {
		return errors.Wrap(err, errUnmarshalCredentials)
	}
	// set credentials configuration
	ps.Configuration[keySubscriptionID] = azureCreds[keyAzureSubscriptionID]
	ps.Configuration[keyTenantID] = azureCreds[keyAzureTenantID]
	ps.Configuration[keyClientID] = azureCreds[keyAzureClientID]
	ps.Configuration[keyClientSecret] = azureCreds[keyAzureClientSecret]
	// Override with ProviderConfig spec values if provided
	if pcSpec.SubscriptionID != nil {
		ps.Configuration[keySubscriptionID] = *pcSpec.SubscriptionID
	}
	if pcSpec.TenantID != nil {
		ps.Configuration[keyTenantID] = *pcSpec.TenantID
	}
	if pcSpec.ClientID != nil {
		ps.Configuration[keyClientID] = *pcSpec.ClientID
	}
	if pcSpec.Environment != nil {
		ps.Configuration[keyEnvironment] = *pcSpec.Environment
	}
	return nil
}

// msiAuth configures Managed Service Identity authentication
func msiAuth(pcSpec *namespacedv1beta1.ProviderConfigSpec, ps *terraform.Setup) error {
	if pcSpec.TenantID == nil || len(*pcSpec.TenantID) == 0 {
		return errors.New(errTenantIDNotSet)
	}
	if pcSpec.SubscriptionID == nil || len(*pcSpec.SubscriptionID) == 0 {
		return errors.New(errSubscriptionIDNotSet)
	}
	ps.Configuration[keySubscriptionID] = *pcSpec.SubscriptionID
	ps.Configuration[keyTenantID] = *pcSpec.TenantID
	ps.Configuration[keyUseMSI] = true
	if pcSpec.ClientID != nil {
		ps.Configuration[keyClientID] = *pcSpec.ClientID
	}
	if pcSpec.Environment != nil {
		ps.Configuration[keyEnvironment] = *pcSpec.Environment
	}
	return nil
}

// oidcAuth configures OIDC/Workload Identity authentication
func oidcAuth(pcSpec *namespacedv1beta1.ProviderConfigSpec, ps *terraform.Setup) error {
	if pcSpec.TenantID == nil || len(*pcSpec.TenantID) == 0 {
		return errors.New(errTenantIDNotSet)
	}
	if pcSpec.ClientID == nil || len(*pcSpec.ClientID) == 0 {
		return errors.New(errClientIDNotSet)
	}
	if pcSpec.SubscriptionID == nil || len(*pcSpec.SubscriptionID) == 0 {
		return errors.New(errSubscriptionIDNotSet)
	}
	// OIDC Token File Path defaults to a projected-volume path mounted in the pod
	// running in the AKS cluster, when workload identity is enabled on the pod.
	oidcTokenFilePath := defaultOidcTokenFilePath
	if pcSpec.OIDCTokenFilePath != nil {
		oidcTokenFilePath = *pcSpec.OIDCTokenFilePath
	}
	ps.Configuration[keySubscriptionID] = *pcSpec.SubscriptionID
	ps.Configuration[keyTenantID] = *pcSpec.TenantID
	ps.Configuration[keyClientID] = *pcSpec.ClientID
	ps.Configuration[keyOIDCTokenFilePath] = oidcTokenFilePath
	ps.Configuration[keyUseOIDC] = true
	ps.Configuration[keyUseAKSWorkloadID] = true
	if pcSpec.Environment != nil {
		ps.Configuration[keyEnvironment] = *pcSpec.Environment
	}
	return nil
}

func legacyToModernProviderConfigSpec(pc *clusterv1beta1.ProviderConfig) (*namespacedv1beta1.ProviderConfigSpec, error) {
	if pc == nil {
		return nil, nil
	}
	data, err := json.Marshal(pc.Spec)
	if err != nil {
		return nil, err
	}

	var mSpec namespacedv1beta1.ProviderConfigSpec
	err = json.Unmarshal(data, &mSpec)
	return &mSpec, err
}

func enrichLocalSecretRefs(pc *namespacedv1beta1.ProviderConfig, mg resource.Managed) {
	if pc != nil && pc.Spec.Credentials.SecretRef != nil {
		pc.Spec.Credentials.SecretRef.Namespace = mg.GetNamespace()
	}
}

func resolveProviderConfig(ctx context.Context, crClient client.Client, mg resource.Managed) (*namespacedv1beta1.ProviderConfigSpec, error) {
	switch managed := mg.(type) {
	case resource.LegacyManaged:
		return resolveProviderConfigLegacy(ctx, crClient, managed)
	case resource.ModernManaged:
		return resolveProviderConfigModern(ctx, crClient, managed)
	default:
		return nil, errors.New("resource is not a managed")
	}
}

func resolveProviderConfigLegacy(ctx context.Context, client client.Client, mg resource.LegacyManaged) (*namespacedv1beta1.ProviderConfigSpec, error) {
	configRef := mg.GetProviderConfigReference()
	if configRef == nil {
		return nil, errors.New(errNoProviderConfig)
	}
	pc := &clusterv1beta1.ProviderConfig{}
	if err := client.Get(ctx, types.NamespacedName{Name: configRef.Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetProviderConfig)
	}

	t := resource.NewLegacyProviderConfigUsageTracker(client, &clusterv1beta1.ProviderConfigUsage{})
	if err := t.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackUsage)
	}

	return legacyToModernProviderConfigSpec(pc)
}

func resolveProviderConfigModern(ctx context.Context, crClient client.Client, mg resource.ModernManaged) (*namespacedv1beta1.ProviderConfigSpec, error) {
	configRef := mg.GetProviderConfigReference()
	if configRef == nil {
		return nil, errors.New(errNoProviderConfig)
	}

	pcRuntimeObj, err := crClient.Scheme().New(namespacedv1beta1.SchemeGroupVersion.WithKind(configRef.Kind))
	if err != nil {
		return nil, errors.Wrapf(err, "referenced provider config kind %q is invalid for %s/%s", configRef.Kind, mg.GetNamespace(), mg.GetName())
	}
	pcObj, ok := pcRuntimeObj.(resource.ProviderConfig)
	if !ok {
		return nil, errors.Errorf("referenced provider config kind %q is not a provider config type %s/%s", configRef.Kind, mg.GetNamespace(), mg.GetName())
	}

	// Namespace will be ignored if the PC is a cluster-scoped type
	if err := crClient.Get(ctx, types.NamespacedName{Name: configRef.Name, Namespace: mg.GetNamespace()}, pcObj); err != nil {
		return nil, errors.Wrap(err, errGetProviderConfig)
	}

	var pcSpec namespacedv1beta1.ProviderConfigSpec
	switch pc := pcObj.(type) {
	case *namespacedv1beta1.ProviderConfig:
		enrichLocalSecretRefs(pc, mg)
		pcSpec = pc.Spec
	case *namespacedv1beta1.ClusterProviderConfig:
		pcSpec = pc.Spec
	default:
		return nil, errors.New("unknown provider config kind")
	}
	t := resource.NewProviderConfigUsageTracker(crClient, &namespacedv1beta1.ProviderConfigUsage{})
	if err := t.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackUsage)
	}
	return &pcSpec, nil
}
