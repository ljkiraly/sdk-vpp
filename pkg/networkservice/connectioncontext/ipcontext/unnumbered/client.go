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

package unnumbered

import (
	"context"

	"github.com/networkservicemesh/govpp/binapi/interface_types"
	"github.com/pkg/errors"

	"github.com/golang/protobuf/ptypes/empty"
	"go.fd.io/govpp/api"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/ljkiraly/sdk/pkg/networkservice/core/next"
	"github.com/ljkiraly/sdk/pkg/networkservice/utils/metadata"
	"github.com/ljkiraly/sdk/pkg/tools/postpone"
)

type unnumberedClient struct {
	vppConn     api.Connection
	loadIfaceFn func(ctx context.Context, isClient bool) (value interface_types.InterfaceIndex, ok bool)
}

// NewClient creates a new instance of unnumbered client
func NewClient(vppConn api.Connection, loadIfaceFn func(ctx context.Context, isClient bool) (value interface_types.InterfaceIndex, ok bool)) networkservice.NetworkServiceClient {
	return &unnumberedClient{
		vppConn:     vppConn,
		loadIfaceFn: loadIfaceFn,
	}
}

func (u *unnumberedClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	postponeCtxFunc := postpone.ContextWithValues(ctx)

	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}

	if err := addDel(ctx, u.vppConn, metadata.IsClient(u), true, u.loadIfaceFn); err != nil {
		closeCtx, cancelClose := postponeCtxFunc()
		defer cancelClose()

		if _, closeErr := u.Close(closeCtx, conn, opts...); closeErr != nil {
			err = errors.Wrapf(err, "connection closed with error: %s", closeErr.Error())
		}
		return nil, err
	}

	return conn, nil
}

func (u *unnumberedClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	deleteFromMap(ctx, metadata.IsClient(u))
	return next.Client(ctx).Close(ctx, conn, opts...)
}
