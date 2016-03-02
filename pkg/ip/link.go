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

package ip

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/vishvananda/netlink"
)

func makeVethPair(name, peer string, mtu int) (netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Flags: net.FlagUp,
			MTU:   mtu,
		},
		PeerName: peer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, err
	}

	return veth, nil
}

func makeVeth(namePrefix string, mtu int) (peerName string, veth netlink.Link, err error) {
	for i := 0; i < 10; i++ {
		peerName, err = RandomIfaceName(namePrefix)
		if err != nil {
			return
		}

		var name string
		name, err = RandomIfaceName(namePrefix)
		if err != nil {
			return
		}

		veth, err = makeVethPair(name, peerName, mtu)
		switch {
		case err == nil:
			return

		case os.IsExist(err):
			continue

		default:
			err = fmt.Errorf("failed to make veth pair: %v", err)
			return
		}
	}

	// should really never be hit
	err = fmt.Errorf("failed to find a unique veth name")
	return
}

// RandomIfaceName returns string @prefix with random suffix (hashed from entropy).
// prefix can be up to 12 characters in length.
func RandomIfaceName(prefix string) (string, error) {
	const entropyLen = 4
	const maxPrefixLen = syscall.IFNAMSIZ - entropyLen

	if len(prefix) > maxPrefixLen {
		return "", fmt.Errorf("prefix %q too long (up to %d characters)", prefix, maxPrefixLen)
	}
	entropy := make([]byte, entropyLen)
	_, err := rand.Reader.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	// NetworkManager (1.0+) will ignore externally created virtual interfaces
	return fmt.Sprintf("%s%x", prefix, entropy), nil
}

func RenameLink(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err == nil {
		err = netlink.LinkSetName(link, newName)
	}
	return err
}

// SetupVeth sets up a virtual ethernet link.
// Should be in container netns, and will switch back to hostNS to set the host
// veth end up.  If @contVethName is given the container interface will have
// that name or an error will be returned.  If instead @contVethPrefix is
// given the container interface name will be constructed from that prefix
// and will be a unique name in the namespace.
func SetupVeth(contVethName, contVethPrefix string, mtu int, hostNS ns.NetNS) (hostVeth, contVeth netlink.Link, err error) {
	var hostVethName string
	hostVethName, contVeth, err = makeVeth(contVethPrefix, mtu)
	if err != nil {
		return
	}
	if contVethName != "" {
		err = RenameLink(contVeth.Attrs().Name, contVethName)
		if err != nil {
			return
		}
	}

	// Re-fetch container veth to get all properties/attributes
	contVeth, err = netlink.LinkByName(contVethName)
	if err != nil {
		err = fmt.Errorf("failed to lookup %q: %v", contVethName, err)
		return
	}

	if err = netlink.LinkSetUp(contVeth); err != nil {
		err = fmt.Errorf("failed to set %q up: %v", contVethName, err)
		return
	}

	hostVeth, err = netlink.LinkByName(hostVethName)
	if err != nil {
		err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
		return
	}

	if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
		err = fmt.Errorf("failed to move veth to host netns: %v", err)
		return
	}

	err = hostNS.Do(func(_ ns.NetNS) error {
		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q in %q: %v", hostVethName, hostNS.Path(), err)
		}

		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}
		return nil
	})
	return
}

// DelLinkByName removes an interface link.
func DelLinkByName(ifName string) error {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return nil
}

// DelLinkByNameAddr remove an interface returns its IP address
// of the specified family
func DelLinkByNameAddr(ifName string, family int) (*net.IPNet, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	addrs, err := netlink.AddrList(iface, family)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("failed to get IP addresses for %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return nil, fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return addrs[0].IPNet, nil
}
