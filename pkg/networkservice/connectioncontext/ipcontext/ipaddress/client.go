// Copyright (c) 2020-2023 Cisco and/or its affiliates.
//
// Copyright (c) 2021-2023 Doc.ai and/or its affiliates.
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

package ipaddress

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"go.fd.io/govpp/api"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/ljkiraly/sdk/pkg/networkservice/core/next"
	"github.com/ljkiraly/sdk/pkg/networkservice/utils/metadata"
	"github.com/ljkiraly/sdk/pkg/tools/postpone"

	"github.com/ljkiraly/sdk-vpp/pkg/tools/ifindex"
)

type ipaddressClient struct {
	vppConn api.Connection

	loadIfIndex ifIndexFunc
}

// NewClient creates a NetworkServiceClient chain element to set the ip address on a vpp interface
// It sets the IP Address on the *vpp* side of an interface leaving the
// Endpoint.
//
//	           Endpoint
//	+---------------------------+
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|      ipaddress.NewClient()+-------------------+
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	|                           |
//	+---------------------------+
func NewClient(vppConn api.Connection, opts ...Option) networkservice.NetworkServiceClient {
	o := &options{
		loadIfIndex: ifindex.Load,
	}
	for _, opt := range opts {
		opt(o)
	}

	return &ipaddressClient{
		vppConn:     vppConn,
		loadIfIndex: o.loadIfIndex,
	}
}

func (i *ipaddressClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	postponeCtxFunc := postpone.ContextWithValues(ctx)

	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}

	if err := addDel(ctx, conn, i.vppConn, i.loadIfIndex, metadata.IsClient(i), true); err != nil {
		closeCtx, cancelClose := postponeCtxFunc()
		defer cancelClose()

		if _, closeErr := i.Close(closeCtx, conn, opts...); closeErr != nil {
			err = errors.Wrapf(err, "connection closed with error: %s", closeErr.Error())
		}

		return nil, err
	}

	return conn, nil
}

func (i *ipaddressClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	// We don't need to remove the address on closing.
	// In most cases, Close also removes the target interface and the address will be deleted along with it.
	// Leaving the address allows us to solve the loopback + unnumbered problem where we don't need to remove the address when the connection is closed.
	return next.Client(ctx).Close(ctx, conn, opts...)
}
