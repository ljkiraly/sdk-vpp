// Copyright (c) 2020-2023 Cisco and/or its affiliates.
//
// Copyright (c) 2021-2023 Nordix Foundation.
//
// Copyright (c) 2024 Cisco and/or its affiliates.
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

//go:build linux
// +build linux

package forwarder

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.fd.io/govpp/api"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	ipsecapi "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/ipsec"

	"github.com/ljkiraly/sdk/pkg/networkservice/chains/client"
	"github.com/ljkiraly/sdk/pkg/networkservice/chains/endpoint"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/authorize"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/cleanup"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/connect"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/discover"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/filtermechanisms"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/mechanismpriority"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/mechanisms"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/mechanismtranslation"
	"github.com/ljkiraly/sdk/pkg/networkservice/common/roundrobin"
	"github.com/ljkiraly/sdk/pkg/tools/log"
	authmonitor "github.com/ljkiraly/sdk/pkg/tools/monitorconnection/authorize"
	"github.com/ljkiraly/sdk/pkg/tools/token"

	registryclient "github.com/ljkiraly/sdk/pkg/registry/chains/client"
	"github.com/ljkiraly/sdk/pkg/registry/common/null"
	registryrecvfd "github.com/ljkiraly/sdk/pkg/registry/common/recvfd"
	registrysendfd "github.com/ljkiraly/sdk/pkg/registry/common/sendfd"

	"github.com/ljkiraly/sdk-kernel/pkg/kernel/networkservice/connectioncontextkernel"
	"github.com/ljkiraly/sdk-kernel/pkg/kernel/networkservice/ethernetcontext"

	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/afxdppinhole"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/connectioncontext/mtu"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/ipsec"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/kernel"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/memif"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/vlan"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/vxlan"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/wireguard"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/metrics"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/nsmonitor"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/pinhole"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/tag"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/up"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/xconnect"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/xconnect/l2bridgedomain"
)

type xconnectNSServer struct {
	endpoint.Endpoint
}

// NewServer - returns an implementation of the xconnectns network service
func NewServer(ctx context.Context, tokenGenerator token.GeneratorFunc, vppConn api.Connection, tunnelIP net.IP, options ...Option) endpoint.Endpoint {
	opts := &forwarderOptions{
		name:                             "forwarder-vpp-" + uuid.New().String(),
		authorizeServer:                  authorize.NewServer(authorize.Any()),
		authorizeMonitorConnectionServer: authmonitor.NewMonitorConnectionServer(authmonitor.Any()),
		clientURL:                        &url.URL{Scheme: "unix", Host: "connect.to.socket"},
		dialTimeout:                      time.Millisecond * 300,
		domain2Device:                    make(map[string]string),
	}
	for _, opt := range options {
		opt(opts)
	}
	nseClient := registryclient.NewNetworkServiceEndpointRegistryClient(ctx,
		registryclient.WithClientURL(opts.clientURL),
		registryclient.WithNSEAdditionalFunctionality(
			registryrecvfd.NewNetworkServiceEndpointRegistryClient(),
			registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		),
		registryclient.WithDialTimeout(opts.dialTimeout),
		registryclient.WithDialOptions(opts.dialOpts...),
		registryclient.WithNSEHealClient(null.NewNetworkServiceEndpointRegistryClient()),
		registryclient.WithNSERetryClient(null.NewNetworkServiceEndpointRegistryClient()),
	)
	nsClient := registryclient.NewNetworkServiceRegistryClient(ctx,
		registryclient.WithClientURL(opts.clientURL),
		registryclient.WithDialTimeout(opts.dialTimeout),
		registryclient.WithDialOptions(opts.dialOpts...),
		registryclient.WithNSHealClient(null.NewNetworkServiceRegistryClient()),
		registryclient.WithNSRetryClient(null.NewNetworkServiceRegistryClient()),
	)

	ikev2Key, err := ipsec.GenerateRSAKey()
	if err != nil {
		log.FromContext(ctx).Fatalf("error ipsec.GenerateRSAKey: %v", err.Error())
	}
	rv := &xconnectNSServer{}
	pinholeMutex := new(sync.Mutex)
	additionalFunctionality := []networkservice.NetworkServiceServer{
		recvfd.NewServer(),
		sendfd.NewServer(),
		discover.NewServer(nsClient, nseClient),
		roundrobin.NewServer(),
		metrics.NewServer(ctx, vppConn, opts.metricsOpts...),
		up.NewServer(ctx, vppConn),
		xconnect.NewServer(vppConn),
		l2bridgedomain.NewServer(vppConn),
		connectioncontextkernel.NewServer(),
		ethernetcontext.NewVFServer(),
		tag.NewServer(ctx, vppConn),
		mtu.NewServer(vppConn),
		mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
			memif.MECHANISM: memif.NewServer(ctx, vppConn,
				memif.WithDirectMemif(),
				memif.WithChangeNetNS()),
			kernel.MECHANISM:    kernel.NewServer(vppConn),
			vxlan.MECHANISM:     vxlan.NewServer(vppConn, tunnelIP, opts.vxlanOpts...),
			wireguard.MECHANISM: wireguard.NewServer(vppConn, tunnelIP),
			ipsecapi.MECHANISM:  ipsec.NewServer(vppConn, tunnelIP, ipsec.WithIKEv2PrivateKey(ikev2Key)),
		}),
		afxdppinhole.NewServer(),
		pinhole.NewServer(vppConn, pinhole.WithSharedMutex(pinholeMutex)),
		connect.NewServer(
			client.NewClient(ctx,
				client.WithoutRefresh(),
				client.WithName(opts.name),
				client.WithDialOptions(opts.dialOpts...),
				client.WithDialTimeout(opts.dialTimeout),
				client.WithAdditionalFunctionality(
					append([]networkservice.NetworkServiceClient{
						cleanup.NewClient(ctx, opts.cleanupOpts...),
						mechanismtranslation.NewClient(),
						connectioncontextkernel.NewClient(),
						metrics.NewClient(ctx, vppConn, opts.metricsOpts...),
						up.NewClient(ctx, vppConn),
						mtu.NewClient(vppConn),
						tag.NewClient(ctx, vppConn),
						// mechanisms
						memif.NewClient(ctx, vppConn,
							memif.WithChangeNetNS(),
						),
						kernel.NewClient(vppConn),
						vxlan.NewClient(vppConn, tunnelIP, opts.vxlanOpts...),
						wireguard.NewClient(vppConn, tunnelIP),
						ipsec.NewClient(vppConn, tunnelIP, ipsec.WithIKEv2PrivateKey(ikev2Key)),
						vlan.NewClient(vppConn, opts.domain2Device),
						filtermechanisms.NewClient(),
						mechanismpriority.NewClient(opts.mechanismPrioriyList...),
						afxdppinhole.NewClient(),
						pinhole.NewClient(vppConn, pinhole.WithSharedMutex(pinholeMutex)),
						recvfd.NewClient(),
						nsmonitor.NewClient(ctx),
						sendfd.NewClient(),
					},
						opts.clientAdditionalFunctionality...,
					)...,
				),
			),
		),
	}

	rv.Endpoint = endpoint.NewServer(ctx, tokenGenerator,
		endpoint.WithName(opts.name),
		endpoint.WithAuthorizeServer(opts.authorizeServer),
		endpoint.WithAuthorizeMonitorConnectionServer(opts.authorizeMonitorConnectionServer),
		endpoint.WithAdditionalFunctionality(additionalFunctionality...))

	return rv
}
