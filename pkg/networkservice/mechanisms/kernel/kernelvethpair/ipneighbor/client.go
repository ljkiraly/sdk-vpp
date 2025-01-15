// Copyright (c) 2021-2023 Cisco and/or its affiliates.
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

package ipneighbor

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"go.fd.io/govpp/api"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	"github.com/ljkiraly/sdk/pkg/networkservice/core/next"
	"github.com/ljkiraly/sdk/pkg/networkservice/utils/metadata"
	"github.com/ljkiraly/sdk/pkg/tools/postpone"
)

type ipneighborClient struct {
	vppConn api.Connection
}

// NewClient - creates new ipneigbor client chain element to correct for the L2 nature of vethpairs when used for payload.IP
func NewClient(vppConn api.Connection) networkservice.NetworkServiceClient {
	return &ipneighborClient{
		vppConn: vppConn,
	}
}

func (i *ipneighborClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	if request.GetConnection().GetPayload() != payload.IP {
		return next.Client(ctx).Request(ctx, request, opts...)
	}

	postponeCtxFunc := postpone.ContextWithValues(ctx)

	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}

	if err := addDel(ctx, conn, i.vppConn, metadata.IsClient(i), true); err != nil {
		closeCtx, cancelClose := postponeCtxFunc()
		defer cancelClose()

		if _, closeErr := i.Close(closeCtx, conn, opts...); closeErr != nil {
			err = errors.Wrapf(err, "connection closed with error: %s", closeErr.Error())
		}

		return nil, err
	}

	return conn, nil
}

func (i *ipneighborClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	if conn.GetPayload() != payload.IP {
		return next.Client(ctx).Close(ctx, conn, opts...)
	}
	_ = addDel(ctx, conn, i.vppConn, metadata.IsClient(i), false)
	return next.Client(ctx).Close(ctx, conn, opts...)
}
