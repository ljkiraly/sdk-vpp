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

package metrics

import (
	"context"

	"go.fd.io/govpp/api"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/ljkiraly/sdk/pkg/networkservice/core/chain"

	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/metrics/ifacename"
	"github.com/ljkiraly/sdk-vpp/pkg/networkservice/metrics/stats"
)

// NewServer provides NetworkServiceServer chain elements that retrieve vpp interface statistics and names.
func NewServer(ctx context.Context, vppConn api.Connection, options ...Option) networkservice.NetworkServiceServer {
	opts := &metricsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	return chain.NewNetworkServiceServer(
		stats.NewServer(ctx, stats.WithSocket(opts.socket)),
		ifacename.NewServer(ctx, vppConn, ifacename.WithSocket(opts.socket)),
	)
}
