// Copyright (c) 2020-2023 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mtu

import (
	"context"
	"io"
	"net"

	"github.com/pkg/errors"
	"go.fd.io/govpp/api"

	interfaces "github.com/networkservicemesh/govpp/binapi/interface"
	"github.com/networkservicemesh/govpp/binapi/ip"

	"github.com/ljkiraly/sdk-vpp/pkg/tools/types"
)

func getMTU(ctx context.Context, vppConn api.Connection, tunnelIP net.IP) (uint32, error) {
	client, err := interfaces.NewServiceClient(vppConn).SwInterfaceDump(ctx, &interfaces.SwInterfaceDump{})
	if err != nil {
		return 0, errors.Wrapf(err, "error attempting to get interface dump client to determine MTU for tunnelIP %q", tunnelIP)
	}
	defer func() { _ = client.Close() }()

	for {
		details, err := client.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, errors.Wrapf(err, "error attempting to get interface details to determine MTU for tunnelIP %q", tunnelIP)
		}

		ipAddressClient, err := ip.NewServiceClient(vppConn).IPAddressDump(ctx, &ip.IPAddressDump{
			SwIfIndex: details.SwIfIndex,
			IsIPv6:    tunnelIP.To4() == nil,
		})
		if err != nil {
			return 0, errors.Wrapf(err, "error attempting to get ip address for vpp interface %q determine MTU for tunnelIP %q", details.InterfaceName, tunnelIP)
		}
		defer func() { _ = ipAddressClient.Close() }()

		for {
			ipAddressDetails, err := ipAddressClient.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return 0, errors.Wrapf(err, "error attempting to get interface ip address for %q (swIfIndex: %q) to determine MTU for tunnelIP %q", details.InterfaceName, details.SwIfIndex, tunnelIP)
			}
			if types.FromVppAddressWithPrefix(ipAddressDetails.Prefix).IP.Equal(tunnelIP) && details.Mtu[0] != 0 {
				return (details.Mtu[0] - overhead(tunnelIP.To4() == nil)), nil
			}
		}
	}
	return 0, errors.Errorf("unable to find interface in vpp with tunnelIP: %q or interface IP MTU is zero", tunnelIP)
}

func overhead(isV6 bool) uint32 {
	if !isV6 {
		// outer ipv4 header - 20 bytes
		// outer udp header - 8 bytes
		// vxlan header - 8 bytes
		// inner ethernet header - 14 bytes
		// optional overhead for 802.1q vlan tags - 4 bytes
		// total - 54 bytes
		return 54
	}
	// outer ipv6 header - 40 bytes
	// outer udp header - 8 bytes
	// vxlan header - 8 bytes
	// inner ethernet header - 14 bytes
	// optional overhead for 802.1q vlan tags - 4 bytes
	// total - 74 bytes
	return 74
}
