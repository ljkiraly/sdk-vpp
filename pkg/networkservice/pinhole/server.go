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

package pinhole

import (
	"context"
	"fmt"
	"sync"

	"github.com/edwarnicke/genericsync"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"go.fd.io/govpp/api"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/ljkiraly/sdk/pkg/networkservice/core/next"
	"github.com/ljkiraly/sdk/pkg/networkservice/utils/metadata"
	"github.com/ljkiraly/sdk/pkg/tools/postpone"
)

type pinholeServer struct {
	vppConn   api.Connection
	ipPortMap genericsync.Map[IPPort, struct{}]

	// We need to protect ACL rules applying with a mutex.
	// Because adding new entries is based on a dump and applying modified data.
	// This must be an atomic operation, otherwise a data race is possible.
	mutex *sync.Mutex
}

// NewServer - returns a new client that will set an ACL permitting remote protocols packets through if and only if there's an ACL on the interface
func NewServer(vppConn api.Connection, opts ...Option) networkservice.NetworkServiceServer {
	o := &option{
		mutex: new(sync.Mutex),
	}
	for _, opt := range opts {
		opt(o)
	}

	return &pinholeServer{
		vppConn: vppConn,
		mutex:   o.mutex,
	}
}

func (v *pinholeServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	postponeCtxFunc := postpone.ContextWithValues(ctx)

	conn, err := next.Server(ctx).Request(ctx, request)
	if err != nil {
		return nil, err
	}

	keys := []*IPPort{
		fromMechanism(conn.GetMechanism(), metadata.IsClient(v)),
		fromContext(ctx, metadata.IsClient(v)),
	}
	for _, key := range keys {
		if key == nil {
			continue
		}
		// Check if this ACL rule has been added
		if _, ok := v.ipPortMap.Load(*key); !ok {
			var err error

			v.mutex.Lock()
			// Double check after mutex
			if _, ok := v.ipPortMap.Load(*key); !ok {
				if err = create(ctx, v.vppConn, key.IP(), key.Port(), fmt.Sprintf("%s port %d", aclTag, key.port)); err == nil {
					v.ipPortMap.Store(*key, struct{}{})
				}
			}
			v.mutex.Unlock()

			if err != nil {
				closeCtx, cancelClose := postponeCtxFunc()
				defer cancelClose()

				if _, closeErr := v.Close(closeCtx, conn); closeErr != nil {
					err = errors.Wrapf(err, "connection closed with error: %s", closeErr.Error())
				}
				return nil, err
			}
		}
	}

	return conn, nil
}

func (v *pinholeServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	return next.Server(ctx).Close(ctx, conn)
}
