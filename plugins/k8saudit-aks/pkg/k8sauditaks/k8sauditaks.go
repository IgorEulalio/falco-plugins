package k8sauditaks

import (
	"log"
	"regexp"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
)

const pluginName = "k8saudit-aks"
const regExpAuditID = `"auditID":[ a-z0-9-"]+`

var regExpCAuditID *regexp.Regexp

type Plugin struct {
	k8saudit.Plugin
	Logger *log.Logger
	Config PluginConfig
}

type PluginConfig struct {
	EventHubNamespaceConnectionString string `json:"event_hub_namespace_connection_string" jsonschema:"title=event_hub_namespace_connection_string,description=The connection string of the EventHub Namespace to read from"`
	EventHubName                      string `json:"event_hub_name" jsonschema:"title=event_hub_name,description=The name of the EventHub to read from"`
	BlobStorageConnectionString       string `json:"blob_storage_connection_string" jsonschema:"title=blob_storage_connection_string,description=The connection string of the Blob Storage to use as checkpoint store"`
	BlobStorageContainerName          string `json:"blob_storage_container_name" jsonschema:"title=blob_storage_container_name,description=The name of the Blob Storage container to use as checkpoint store"`
	RateLimitEventsPerSecond          int    `json:"rate_limit_events_per_second" jsonschema:"title=rate_limit_events_per_second,description=The rate limit of events per second to read from EventHub"`
	RateLimitBurst                    int    `json:"rate_limit_burst" jsonschema:"title=rate_limit_burst,description=The rate limit burst of events to read from EventHub"`
}

func (k *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          10,
		Name:        pluginName,
		Description: "Read Kubernetes Audit Events for AKS from EventHub and use blob storage as checkpoint store",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.1.0",
		EventSource: "k8s_audit",
	}
}
