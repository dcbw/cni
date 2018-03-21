// Copyright 2015 CNI authors
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

package libcni

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

var (
	CacheDir = "/var/lib/cni"
)

type RuntimeConf struct {
	ContainerID string
	NetNS       string
	IfName      string
	Args        [][2]string
	// A dictionary of capability-specific data passed by the runtime
	// to plugins as top-level keys in the 'runtimeConfig' dictionary
	// of the plugin's stdin data.  libcni will ensure that only keys
	// in this map which match the capabilities of the plugin are passed
	// to the plugin
	CapabilityArgs map[string]interface{}

	// A cache directory in which to library data.  Defaults to CacheDir
	CacheDir string
}

type NetworkConfig struct {
	Network *types.NetConf
	Bytes   []byte
}

type NetworkConfigList struct {
	Name       string
	CNIVersion string
	Plugins    []*NetworkConfig
	Bytes      []byte
}

type CNI interface {
	AddNetworkList(net *NetworkConfigList, rt *RuntimeConf) (types.Result, error)
	GetNetworkList(net *NetworkConfigList, rt *RuntimeConf) (types.Result, error)
	DelNetworkList(net *NetworkConfigList, rt *RuntimeConf) error

	AddNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error)
	GetNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error)
	DelNetwork(net *NetworkConfig, rt *RuntimeConf) error
}

type CNIConfig struct {
	Path []string
}

// CNIConfig implements the CNI interface
var _ CNI = &CNIConfig{}

func buildOneConfig(name, cniVersion string, orig *NetworkConfig, prevResult types.Result, rt *RuntimeConf) (*NetworkConfig, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"cniVersion": cniVersion,
	}
	// Add previous plugin result
	if prevResult != nil {
		inject["prevResult"] = prevResult
	}

	// Ensure every config uses the same name and version
	orig, err = InjectConf(orig, inject)
	if err != nil {
		return nil, err
	}

	return injectRuntimeConfig(orig, rt)
}

// This function takes a libcni RuntimeConf structure and injects values into
// a "runtimeConfig" dictionary in the CNI network configuration JSON that
// will be passed to the plugin on stdin.
//
// Only "capabilities arguments" passed by the runtime are currently injected.
// These capabilities arguments are filtered through the plugin's advertised
// capabilities from its config JSON, and any keys in the CapabilityArgs
// matching plugin capabilities are added to the "runtimeConfig" dictionary
// sent to the plugin via JSON on stdin.  For exmaple, if the plugin's
// capabilities include "portMappings", and the CapabilityArgs map includes a
// "portMappings" key, that key and its value are added to the "runtimeConfig"
// dictionary to be passed to the plugin's stdin.
func injectRuntimeConfig(orig *NetworkConfig, rt *RuntimeConf) (*NetworkConfig, error) {
	var err error

	rc := make(map[string]interface{})
	for capability, supported := range orig.Network.Capabilities {
		if !supported {
			continue
		}
		if data, ok := rt.CapabilityArgs[capability]; ok {
			rc[capability] = data
		}
	}

	if len(rc) > 0 {
		orig, err = InjectConf(orig, map[string]interface{}{"runtimeConfig": rc})
		if err != nil {
			return nil, err
		}
	}

	return orig, nil
}

func (c *CNIConfig) addOrGetNetwork(command, name, cniVersion string, net *NetworkConfig, prevResult types.Result, rt *RuntimeConf) (types.Result, error) {
	pluginPath, err := invoke.FindInPath(net.Network.Type, c.Path)
	if err != nil {
		return nil, err
	}

	newConf, err := buildOneConfig(name, cniVersion, net, prevResult, rt)
	if err != nil {
		return nil, err
	}

	return invoke.ExecPluginWithResult(pluginPath, newConf.Bytes, c.args(command, rt))
}

// Note that only GET requests should pass an initial prevResult
func (c *CNIConfig) addOrGetNetworkList(command string, prevResult types.Result, list *NetworkConfigList, rt *RuntimeConf) (types.Result, error) {
	var err error
	for _, net := range list.Plugins {
		prevResult, err = c.addOrGetNetwork(command, list.Name, list.CNIVersion, net, prevResult, rt)
		if err != nil {
			return nil, err
		}
	}

	return prevResult, nil
}

func getResultCacheFilePath(netName string, rt *RuntimeConf) string {
	cacheDir := rt.CacheDir
	if cacheDir == "" {
		cacheDir = CacheDir
	}
	return filepath.Join(cacheDir, "results", fmt.Sprintf("%s-%s", netName, rt.ContainerID))
}

func setCachedResult(result types.Result, netName string, rt *RuntimeConf) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	fname := getResultCacheFilePath(netName, rt)
	if err := os.MkdirAll(filepath.Dir(fname), 0700); err != nil {
		return err
	}
	return ioutil.WriteFile(fname, data, 0600)
}

func getCachedResult(netName, cniVersion string, rt *RuntimeConf) (types.Result, error) {
	fname := getResultCacheFilePath(netName, rt)
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		// Ignore read errors; the cached result may not exist on-disk
		return nil, nil
	}

	// Read the version of the cached result
	decoder := version.ConfigDecoder{}
	resultCniVersion, err := decoder.Decode(data)
	if err != nil {
		return nil, err
	}

	// Ensure we can understand the result
	result, err := version.NewResult(resultCniVersion, data)
	if err != nil {
		return nil, err
	}

	// Convert to the config version to ensure plugins get prevResult
	// in the same version as the config
	result, err = result.GetAsVersion(cniVersion)
	if err != nil && resultCniVersion != cniVersion {
		// The cached result version should match the config version
		// unless the config was changed while the container was
		// running.  If that happens and conversion fails, return a
		// more descriptive error.
		return nil, fmt.Errorf("failed to convert cached result version %q to config version %q: %v", resultCniVersion, cniVersion, err)
	}
	return result, err
}

// AddNetworkList executes a sequence of plugins with the ADD command
func (c *CNIConfig) AddNetworkList(list *NetworkConfigList, rt *RuntimeConf) (types.Result, error) {
	result, err := c.addOrGetNetworkList("ADD", nil, list, rt)
	if err != nil {
		return nil, err
	}

	if err = setCachedResult(result, list.Name, rt); err != nil {
		return nil, err
	}

	return result, nil
}

// GetNetworkList executes a sequence of plugins with the GET command
func (c *CNIConfig) GetNetworkList(list *NetworkConfigList, rt *RuntimeConf) (types.Result, error) {
	cachedResult, err := getCachedResult(list.Name, list.CNIVersion, rt)
	if err != nil {
		return nil, err
	}
	return c.addOrGetNetworkList("GET", cachedResult, list, rt)
}

func (c *CNIConfig) delNetwork(name, cniVersion string, net *NetworkConfig, prevResult types.Result, rt *RuntimeConf) error {
	pluginPath, err := invoke.FindInPath(net.Network.Type, c.Path)
	if err != nil {
		return err
	}

	newConf, err := buildOneConfig(name, cniVersion, net, prevResult, rt)
	if err != nil {
		return err
	}

	return invoke.ExecPluginWithoutResult(pluginPath, newConf.Bytes, c.args("DEL", rt))
}

// DelNetworkList executes a sequence of plugins with the DEL command
func (c *CNIConfig) DelNetworkList(list *NetworkConfigList, rt *RuntimeConf) error {
	cachedResult, err := getCachedResult(list.Name, list.CNIVersion, rt)
	if err != nil {
		return err
	}
	for i := len(list.Plugins) - 1; i >= 0; i-- {
		net := list.Plugins[i]
		if err := c.delNetwork(list.Name, list.CNIVersion, net, cachedResult, rt); err != nil {
			return err
		}
	}

	return nil
}

// AddNetwork executes the plugin with the ADD command
func (c *CNIConfig) AddNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error) {
	result, err := c.addOrGetNetwork("ADD", net.Network.Name, net.Network.CNIVersion, net, nil, rt)
	if err != nil {
		return nil, err
	}

	if err = setCachedResult(result, net.Network.Name, rt); err != nil {
		return nil, err
	}

	return result, nil
}

// GetNetwork executes the plugin with the GET command
func (c *CNIConfig) GetNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error) {
	cachedResult, err := getCachedResult(net.Network.Name, net.Network.CNIVersion, rt)
	if err != nil {
		return nil, err
	}
	return c.addOrGetNetwork("GET", net.Network.Name, net.Network.CNIVersion, net, cachedResult, rt)
}

// DelNetwork executes the plugin with the DEL command
func (c *CNIConfig) DelNetwork(net *NetworkConfig, rt *RuntimeConf) error {
	cachedResult, err := getCachedResult(net.Network.Name, net.Network.CNIVersion, rt)
	if err != nil {
		return err
	}
	return c.delNetwork(net.Network.Name, net.Network.CNIVersion, net, cachedResult, rt)
}

// GetVersionInfo reports which versions of the CNI spec are supported by
// the given plugin.
func (c *CNIConfig) GetVersionInfo(pluginType string) (version.PluginInfo, error) {
	pluginPath, err := invoke.FindInPath(pluginType, c.Path)
	if err != nil {
		return nil, err
	}

	return invoke.GetVersionInfo(pluginPath)
}

// =====
func (c *CNIConfig) args(action string, rt *RuntimeConf) *invoke.Args {
	return &invoke.Args{
		Command:     action,
		ContainerID: rt.ContainerID,
		NetNS:       rt.NetNS,
		PluginArgs:  rt.Args,
		IfName:      rt.IfName,
		Path:        strings.Join(c.Path, string(os.PathListSeparator)),
	}
}
