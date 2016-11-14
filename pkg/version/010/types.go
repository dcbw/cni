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

package types010

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/types"
)

// Compatibility types for CNI version 0.1.0 and 0.2.0

// Result is what gets returned from the plugin (via stdout) to the caller
type Result struct {
	IP4 *IPConfig `json:"ip4,omitempty"`
	IP6 *IPConfig `json:"ip6,omitempty"`
	DNS types.DNS `json:"dns,omitempty"`
}

func (r *Result) Print() error {
	data, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

// String returns a formatted string in the form of "[IP4: $1,][ IP6: $2,] DNS: $3" where
// $1 represents the receiver's IPv4, $2 represents the receiver's IPv6 and $3 the
// receiver's DNS. If $1 or $2 are nil, they won't be present in the returned string.
func (r *Result) String() string {
	var str string
	if r.IP4 != nil {
		str = fmt.Sprintf("IP4:%+v, ", *r.IP4)
	}
	if r.IP6 != nil {
		str += fmt.Sprintf("IP6:%+v, ", *r.IP6)
	}
	return fmt.Sprintf("%sDNS:%+v", str, r.DNS)
}

// Convert this old version result to the current CNI version result
func (r *Result) Convert() (*types.Result, error) {
	newResult := &types.Result{
		DNS: r.DNS,
	}

	if r.IP4 != nil && r.IP4.IP.IP.To4() != nil {
		newResult.IP = append(newResult.IP, &types.IPConfig{
			Version:   "4",
			Interface: -1,
			Address:   r.IP4.IP,
			Gateway:   r.IP4.Gateway,
			Routes:    r.IP4.Routes,
		})
	}

	if r.IP6 != nil && r.IP6.IP.IP.To16() != nil {
		newResult.IP = append(newResult.IP, &types.IPConfig{
			Version:   "6",
			Interface: -1,
			Address:   r.IP6.IP,
			Gateway:   r.IP6.Gateway,
			Routes:    r.IP6.Routes,
		})
	}

	if len(newResult.IP) == 0 {
		return nil, fmt.Errorf("cannot convert: no valid IP addresses")
	}

	return newResult, nil
}

// IPConfig contains values necessary to configure an interface
type IPConfig struct {
	IP      net.IPNet
	Gateway net.IP
	Routes  []types.Route
}

// net.IPNet is not JSON (un)marshallable so this duality is needed
// for our custom IPNet type

// JSON (un)marshallable types
type ipConfig struct {
	IP      types.IPNet `json:"ip"`
	Gateway net.IP  `json:"gateway,omitempty"`
	Routes  []types.Route `json:"routes,omitempty"`
}

func (c *IPConfig) MarshalJSON() ([]byte, error) {
	ipc := ipConfig{
		IP:      types.IPNet(c.IP),
		Gateway: c.Gateway,
		Routes:  c.Routes,
	}

	return json.Marshal(ipc)
}

func (c *IPConfig) UnmarshalJSON(data []byte) error {
	ipc := ipConfig{}
	if err := json.Unmarshal(data, &ipc); err != nil {
		return err
	}

	c.IP = net.IPNet(ipc.IP)
	c.Gateway = ipc.Gateway
	c.Routes = ipc.Routes
	return nil
}
