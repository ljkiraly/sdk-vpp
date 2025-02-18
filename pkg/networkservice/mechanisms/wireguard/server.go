// Copyright (c) 2021-2023 Doc.ai and/or its affiliates.
//
// Copyright (c) 2022-2023 Cisco and/or its affiliates.
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

package wireguard

import (
	"context"
	"net"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"go.fd.io/govpp/api"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	wireguardMech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/wireguard"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	"github.com/ljkiraly/sdk/pkg/networkservice/core/chain"
	"github.com/ljkiraly/sdk/pkg/networkservice/core/next"
	"github.com/ljkiraly/sdk/pkg/networkservice/utils/metadata"
	"github.com/ljkiraly/sdk/pkg/tools/postpone"

	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/wireguard/mtu"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/mechanisms/wireguard/peer"
)

type wireguardServer struct {
	vppConn  api.Connection
	tunnelIP net.IP
}

// NewServer - returns a new server for the wireguard remote mechanism
func NewServer(vppConn api.Connection, tunnelIP net.IP) networkservice.NetworkServiceServer {
	return chain.NewNetworkServiceServer(
		peer.NewServer(vppConn),
		mtu.NewServer(vppConn, tunnelIP),
		&wireguardServer{
			vppConn:  vppConn,
			tunnelIP: tunnelIP,
		},
	)
}

func (w *wireguardServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	if request.GetConnection().GetPayload() != payload.IP {
		return next.Server(ctx).Request(ctx, request)
	}
	if mechanism := wireguardMech.ToMechanism(request.GetConnection().GetMechanism()); mechanism != nil {
		mechanism.SetDstIP(w.tunnelIP)
		mechanism.SetDstPort(wireguardDefaultPort)
	}

	postponeCtxFunc := postpone.ContextWithValues(ctx)

	conn, err := next.Server(ctx).Request(ctx, request)
	if err != nil {
		return nil, err
	}

	if mechanism := wireguardMech.ToMechanism(conn.GetMechanism()); mechanism != nil {
		privateKey, _ := wgtypes.GeneratePrivateKey()
		pubKey, err := createInterface(ctx, conn, w.vppConn, privateKey, metadata.IsClient(w))
		if err != nil {
			closeCtx, cancelClose := postponeCtxFunc()
			defer cancelClose()

			if _, closeErr := w.Close(closeCtx, conn); closeErr != nil {
				err = errors.Wrapf(err, "connection closed with error: %s", closeErr.Error())
			}

			return nil, err
		}
		mechanism.SetDstPublicKey(pubKey)
	}

	return conn, nil
}

func (w *wireguardServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	if conn.GetPayload() != payload.IP {
		return next.Server(ctx).Close(ctx, conn)
	}
	_ = delInterface(ctx, conn, w.vppConn, metadata.IsClient(w))
	return next.Server(ctx).Close(ctx, conn)
}
