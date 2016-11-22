// Copyright 2016 CNI authors
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

package current

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/020"
)

const implementedSpecVersion string = "0.3.0"

var SupportedVersions = []string{implementedSpecVersion}

func NewResult(data []byte) (types.Result, error) {
	result := &Result{}
	if err := json.Unmarshal(data, result); err != nil {
		return nil, err
	}
	return result, nil
}

var resultConverters = []struct {
	versions []string
	convert  func(types.Result) (*Result, error)
}{
	{types020.SupportedVersions, convertFrom020},
	{SupportedVersions,          convertFrom030},
}

func convertFrom020(result types.Result) (*Result, error) {
	oldResult, err := types020.GetResult(result)
	if err != nil {
		return nil, err
	}

	newResult := &Result{
		DNS: oldResult.DNS,
	}

	if oldResult.IP4 != nil {
		newResult.IP = append(newResult.IP, &IPConfig{
			Version:   "4",
			Interface: -1,
			Address:   oldResult.IP4.IP,
			Gateway:   oldResult.IP4.Gateway,
			Routes:    oldResult.IP4.Routes,
		})
	}

	if oldResult.IP6 != nil {
		newResult.IP = append(newResult.IP, &IPConfig{
			Version:   "6",
			Interface: -1,
			Address:   oldResult.IP6.IP,
			Gateway:   oldResult.IP6.Gateway,
			Routes:    oldResult.IP6.Routes,
		})
	}

	if len(newResult.IP) == 0 {
		return nil, fmt.Errorf("cannot convert: no valid IP addresses")
	}

	return newResult, nil
}

func convertFrom030(result types.Result) (*Result, error) {
	newResult, ok := result.(*Result)
	if !ok {
		return nil, fmt.Errorf("failed to convert result")
	}
	return newResult, nil
}

func NewResultFromResult(result types.Result) (*Result, error) {
	version := result.Version()
	for _, converter := range resultConverters {
		for _, supportedVersion := range converter.versions {
			if version == supportedVersion {
				return converter.convert(result)
			}
		}
	}
	return nil, fmt.Errorf("unsupported CNI result version %q", version)
}

func GetResult(r types.Result) (*Result, error) {
	resultCurrent, err := r.GetAsVersion(implementedSpecVersion)
	if err != nil {
		return nil, err
	}
	result, ok := resultCurrent.(*Result)
	if !ok {
		return nil, fmt.Errorf("failed to convert result")
	}
	return result, nil
}

// Result is what gets returned from the plugin (via stdout) to the caller
type Result struct {
	Interfaces []*Interface `json:"interfaces,omitempty"`
	IP         []*IPConfig  `json:"ip,omitempty"`
	DNS        types.DNS    `json:"dns,omitempty"`
}

// Convert to the older 0.2.0 CNI spec Result type
func (r *Result) convertTo020() (*types020.Result, error) {
	oldResult := &types020.Result{
		DNS: r.DNS,
	}

	for _, ip := range r.IP {
		if ip.Version == "4" && oldResult.IP4 == nil {
			oldResult.IP4 = &types020.IPConfig{
				IP: ip.Address,
				Gateway: ip.Gateway,
				Routes: ip.Routes,
			}
		} else if ip.Version == "6" && oldResult.IP6 == nil {
			oldResult.IP6 = &types020.IPConfig{
				IP: ip.Address,
				Gateway: ip.Gateway,
				Routes: ip.Routes,
			}
		}
		if oldResult.IP4 != nil && oldResult.IP6 != nil {
			break
		}
	}

	if oldResult.IP4 == nil && oldResult.IP6 == nil {
		return nil, fmt.Errorf("cannot convert: no valid IP addresses")
	}

	return oldResult, nil
}

func (r *Result) Version() string {
	return implementedSpecVersion
}

func (r *Result) GetAsVersion(version string) (types.Result, error) {
	switch version {
	case implementedSpecVersion:
		return r, nil
	case types020.SupportedVersions[0], types020.SupportedVersions[1], types020.SupportedVersions[2]:
		return r.convertTo020()
	}
	return nil, fmt.Errorf("cannot convert version 0.3.0 to %q", version)
}

func (r *Result) GetRaw() ([]byte, error) {
	return json.Marshal(r)
}

func (r *Result) Print() error {
	data, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

// String returns a formatted string in the form of "[Interfaces: $1,][ IP: $2,] DNS: $3" where
// $1 represents the receiver's Interfaces, $2 represents the receiver's IP addresses and $3 the
// receiver's DNS. If $1 or $2 are nil, they won't be present in the returned string.
func (r *Result) String() string {
	var str string
	if len(r.Interfaces) > 0 {
		str += fmt.Sprintf("Interfaces:%+v, ", r.Interfaces)
	}
	if len(r.IP) > 0 {
		str += fmt.Sprintf("IP:%+v, ", r.IP)
	}
	return fmt.Sprintf("%sDNS:%+v", str, r.DNS)
}

// Convert this old version result to the current CNI version result
func (r *Result) Convert() (*Result, error) {
	return r, nil
}

// Interface contains values about the created interfaces
type Interface struct {
	Name    string `json:"name"`
	Mac     string `json:"mac,omitempty"`
	Sandbox string `json:"sandbox,omitempty"`
}

func (i *Interface) String() string {
	return fmt.Sprintf("%+v", *i)
}

// IPConfig contains values necessary to configure an interface
type IPConfig struct {
	// IP version, either "4" or "6"
	Version string
	// Index into Result structs Interfaces list
	Interface int
	Address   net.IPNet
	Gateway   net.IP
	Routes    []types.Route
}

func (i *IPConfig) String() string {
	return fmt.Sprintf("%+v", *i)
}

// JSON (un)marshallable types
type ipConfig struct {
	Version   string        `json:"version"`
	Interface int           `json:"interface,omitempty"`
	Address   types.IPNet   `json:"address"`
	Gateway   net.IP        `json:"gateway,omitempty"`
	Routes    []types.Route `json:"routes,omitempty"`
}

func (c *IPConfig) MarshalJSON() ([]byte, error) {
	ipc := ipConfig{
		Version:   c.Version,
		Interface: c.Interface,
		Address:   types.IPNet(c.Address),
		Gateway:   c.Gateway,
		Routes:    c.Routes,
	}

	return json.Marshal(ipc)
}

func (c *IPConfig) UnmarshalJSON(data []byte) error {
	ipc := ipConfig{}
	if err := json.Unmarshal(data, &ipc); err != nil {
		return err
	}

	c.Version = ipc.Version
	c.Interface = ipc.Interface
	c.Address = net.IPNet(ipc.Address)
	c.Gateway = ipc.Gateway
	c.Routes = ipc.Routes
	return nil
}
