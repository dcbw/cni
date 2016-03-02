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

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// like net.IPNet but adds JSON marshalling and unmarshalling
type IPNet net.IPNet

// ParseCIDR takes a string like "10.2.3.1/24" and
// return IPNet with "10.2.3.1" and /24 mask
func ParseCIDR(s string) (*net.IPNet, error) {
	ip, ipn, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	ipn.IP = ip
	return ipn, nil
}

func (n IPNet) MarshalJSON() ([]byte, error) {
	return json.Marshal((*net.IPNet)(&n).String())
}

func (n *IPNet) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	tmp, err := ParseCIDR(s)
	if err != nil {
		return err
	}

	*n = IPNet(*tmp)
	return nil
}

// NetConf describes a network.
type NetConf struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	IPAM struct {
		Type string `json:"type,omitempty"`
	} `json:"ipam,omitempty"`
	DNS DNS `json:"dns"`
}

// Result is what gets returned from the plugin (via stdout) to the caller
type Result struct {
	Interfaces []*Interface `json:"interfaces,omitempty"`
	IP         []*IPConfig  `json:"ip,omitempty"`
	DNS        DNS          `json:"dns,omitempty"`
}

func (r *Result) Print() error {
	return prettyPrint(r)
}

// String returns a formatted string in the form of "[Interfaces: $1,][ IPs: $2,] DNS: $3" where
// $1 represents the receiver's Interfaces, $2 represents the receiver's IP addresses and $3 the
// receiver's DNS. If $1 or $2 are nil, they won't be present in the returned string.
func (r *Result) String() string {
	var str string
	if len(r.Interfaces) > 0 {
		str += fmt.Sprintf("Interfaces:%+v, ", r.Interfaces)
	}
	if len(r.IP) > 0 {
		str += fmt.Sprintf("IPs:%+v, ", r.IP)
	}
	return fmt.Sprintf("%sDNS:%+v", str, r.DNS)
}

// IPConfig contains values necessary to configure an interface
type IPConfig struct {
	Version   string
	Interface uint
	Address   net.IPNet
	Gateway   net.IP
	Routes    []Route
}

// DNS contains values interesting for DNS resolvers
type DNS struct {
	Nameservers []string `json:"nameservers,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Search      []string `json:"search,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// InterfaceConfig contains values about the created interfaces
type Interface struct {
	Name    string `json:"name"`
	Mac     string `json:"mac,omitempty"`
	Sandbox string `json:"sandbox,omitempty"`
}

type Route struct {
	Dst net.IPNet
	GW  net.IP
}

type Error struct {
	Code    uint   `json:"code"`
	Msg     string `json:"msg"`
	Details string `json:"details,omitempty"`
}

func (e *Error) Error() string {
	return e.Msg
}

func (e *Error) Print() error {
	return prettyPrint(e)
}

// net.IPNet is not JSON (un)marshallable so this duality is needed
// for our custom IPNet type

// JSON (un)marshallable types
type ipConfig struct {
	Version   string  `json:"version"`
	Interface uint    `json:"interface,omitempty"`
	Address   IPNet   `json:"address"`
	Gateway   net.IP  `json:"gateway,omitempty"`
	Routes    []Route `json:"routes,omitempty"`
}

type route struct {
	Dst IPNet  `json:"dst"`
	GW  net.IP `json:"gw,omitempty"`
}

func (c *IPConfig) MarshalJSON() ([]byte, error) {
	ipc := ipConfig{
		Version:   c.Version,
		Interface: c.Interface,
		Address:   IPNet(c.Address),
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

func (r *Route) UnmarshalJSON(data []byte) error {
	rt := route{}
	if err := json.Unmarshal(data, &rt); err != nil {
		return err
	}

	r.Dst = net.IPNet(rt.Dst)
	r.GW = rt.GW
	return nil
}

func (r *Route) MarshalJSON() ([]byte, error) {
	rt := route{
		Dst: IPNet(r.Dst),
		GW:  r.GW,
	}

	return json.Marshal(rt)
}

func prettyPrint(obj interface{}) error {
	data, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}
