// Copyright (c) 2022-2024 Cisco and/or its affiliates.
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

package ipsecup

import (
	"context"
	"time"

	interfaces "github.com/networkservicemesh/govpp/binapi/interface"
	"github.com/networkservicemesh/govpp/binapi/interface_types"
	"github.com/pkg/errors"
	"go.fd.io/govpp/api"

	"github.com/ljkiraly/sdk/pkg/tools/log"

	"github.com/ljkiraly/sdk-vpp/pkg/tools/ifindex"
)

func waitForUpLinkUp(ctx context.Context, vppConn api.Connection, isClient bool) error {
	swIfIndex, ok := ifindex.Load(ctx, isClient)
	if !ok {
		return nil
	}
	watcher, err := vppConn.WatchEvent(ctx, &interfaces.SwInterfaceEvent{})
	if err != nil {
		return errors.Wrap(err, "failed to watch interfaces.SwInterfaceEvent")
	}
	defer func() { watcher.Close() }()

	now := time.Now()
	dc, err := interfaces.NewServiceClient(vppConn).SwInterfaceDump(ctx, &interfaces.SwInterfaceDump{
		SwIfIndex: swIfIndex,
	})
	if err != nil {
		return errors.Wrap(err, "vppapi SwInterfaceDump returned error")
	}
	defer func() { _ = dc.Close() }()

	details, err := dc.Recv()
	if err != nil {
		return errors.Wrapf(err, "error retrieving SwInterfaceDetails for swIfIndex %d", swIfIndex)
	}
	log.FromContext(ctx).
		WithField("swIfIndex", swIfIndex).
		WithField("details.Flags", details.Flags).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceDump").Debug("completed")

	isUp := details.Flags & interface_types.IF_STATUS_API_FLAG_LINK_UP
	if isUp != 0 {
		return nil
	}

	now = time.Now()
	for {
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "provided context is done")
		case rawMsg := <-watcher.Events():
			if msg, ok := rawMsg.(*interfaces.SwInterfaceEvent); ok &&
				msg.SwIfIndex == swIfIndex &&
				msg.Flags&interface_types.IF_STATUS_API_FLAG_LINK_UP != 0 {
				log.FromContext(ctx).
					WithField("swIfIndex", swIfIndex).
					WithField("msg.Flags", msg.Flags).
					WithField("duration", time.Since(now)).
					WithField("vppapi", "SwInterfaceEvent").Debug("completed")
				return nil
			}
		}
	}
}
