// Copyright (c) 2020-2024 Cisco and/or its affiliates.
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

package kernelvethpair

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"

	kernellink "github.com/ljkiraly/sdk-kernel/pkg/kernel"
	"github.com/ljkiraly/sdk-kernel/pkg/kernel/tools/nshandle"
	"github.com/ljkiraly/sdk-kernel/pkg/kernel/tools/peer"
	"github.com/ljkiraly/sdk/pkg/tools/log"

	"github.com/ljkiraly/sdk/pkg/tools/nanoid"

	"github.com/ljkiraly/sdk-vpp/pkg/tools/ethtool"
	"github.com/ljkiraly/sdk-vpp/pkg/tools/link"
	"github.com/ljkiraly/sdk-vpp/pkg/tools/mechutils"
)

func create(ctx context.Context, conn *networkservice.Connection, isClient bool) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		// Construct the netlink handle for the target namespace for this kernel interface
		handle, err := kernellink.GetNetlinkHandle(mechanism.GetNetNSURL())
		if err != nil {
			return err
		}
		defer handle.Close()

		if _, ok := link.Load(ctx, isClient); ok {
			return nil
		}

		// In the forwarder context:
		// link is on the NSC/NSE side, peer is on the forwarder side.
		linkAlias := mechutils.ToAlias(conn, isClient)
		peerAlias := fmt.Sprintf("veth-%s", linkAlias)

		// Delete the previous link if there is one in the target namespace
		var prevLink netlink.Link
		if prevLink, err = handle.LinkByAlias(linkAlias); err == nil {
			now := time.Now()
			if err = handle.LinkDel(prevLink); err != nil {
				return errors.Wrapf(err, "failed to delete link device %v", prevLink)
			}
			log.FromContext(ctx).
				WithField("link.Name", prevLink.Attrs().Name).
				WithField("duration", time.Since(now)).
				WithField("netlink", "LinkDel").Debug("completed")
		}

		// Create the veth pair
		la := netlink.NewLinkAttrs()
		la.Name, err = nanoid.GenerateLinuxInterfaceName(conn.GetNetworkService())
		if err != nil {
			return err
		}
		peerName, err := nanoid.GenerateLinuxInterfaceName(conn.GetNetworkService())
		if err != nil {
			return err
		}

		now := time.Now()
		veth := &netlink.Veth{
			LinkAttrs: la,
			PeerName:  peerName,
		}

		var l netlink.Link = veth
		if addErr := netlink.LinkAdd(l); addErr != nil {
			return errors.Wrapf(addErr, "failed to add new link device %v", l)
		}
		log.FromContext(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("link.PeerName", veth.PeerName).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkAdd").Debug("completed")

		err = ethtool.DisableVethChkSumOffload(veth)
		if err != nil {
			return err
		}

		// Construct the nsHandle for the target namespace for this kernel interface
		nsHandle, err := nshandle.FromURL(mechanism.GetNetNSURL())
		if err != nil {
			return err
		}
		defer func() { _ = nsHandle.Close() }()

		// Set the link l to the correct netns
		now = time.Now()
		if err = netlink.LinkSetNsFd(l, int(nsHandle)); err != nil {
			return errors.Wrapf(err, "unable to change to netns")
		}
		log.FromContext(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetNsFd").Debug("completed")

		// Get the link l in the new namespace
		now = time.Now()
		name := l.Attrs().Name
		l, err = handle.LinkByName(name)
		if err != nil {
			log.FromContext(ctx).
				WithField("duration", time.Since(now)).
				WithField("link.Name", name).
				WithField("err", err).
				WithField("netlink", "LinkByName").Debug("error")
			return errors.Wrapf(err, "failed to get net interface: %v", name)
		}
		log.FromContext(ctx).
			WithField("duration", time.Since(now)).
			WithField("link.Name", name).
			WithField("netlink", "LinkByName").Debug("completed")

		name = mechanism.GetInterfaceName()
		// Set the LinkName
		now = time.Now()
		if err = handle.LinkSetName(l, name); err != nil {
			log.FromContext(ctx).
				WithField("link.Name", l.Attrs().Name).
				WithField("link.NewName", name).
				WithField("duration", time.Since(now)).
				WithField("err", err).
				WithField("netlink", "LinkSetName").Debug("error")
			return errors.Wrapf(err, "failed to set the name(%s) of the link device(%v)", name, l)
		}
		log.FromContext(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("link.NewName", name).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetName").Debug("completed")

		// Set the Link Alias
		now = time.Now()
		if err = handle.LinkSetAlias(l, linkAlias); err != nil {
			return errors.Wrapf(err, "failed to set the alias(%s) of the link device(%v)", linkAlias, l)
		}
		log.FromContext(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("alias", linkAlias).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetAlias").Debug("completed")

		// Up the link
		now = time.Now()
		err = handle.LinkSetUp(l)
		if err != nil {
			return errors.Wrapf(err, "failed to enable the link device: %v", l)
		}
		log.FromContext(ctx).
			WithField("link.Name", l.Attrs().Name).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetUp").Debug("completed")

		// Store the link for use by ipneighbor
		link.Store(ctx, isClient, l)

		// Get the peerLink
		now = time.Now()
		peerLink, err := netlink.LinkByName(veth.PeerName)
		if err != nil {
			_ = netlink.LinkDel(l)
			return errors.Wrapf(err, "failed to get net interface: %v", name)
		}
		log.FromContext(ctx).
			WithField("link.Name", veth.PeerName).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkByName").Debug("completed")

		// Set Alias of peerLink
		now = time.Now()
		if err = netlink.LinkSetAlias(peerLink, peerAlias); err != nil {
			_ = netlink.LinkDel(l)
			_ = netlink.LinkDel(peerLink)
			return errors.Wrapf(err, "failed to set the alias(%s) of the link device(%v)", peerAlias, peerLink)
		}
		log.FromContext(ctx).
			WithField("link.Name", peerLink.Attrs().Name).
			WithField("peerLink", peerAlias).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetAlias").Debug("completed")

		// Up the peerLink
		now = time.Now()
		err = netlink.LinkSetUp(peerLink)
		if err != nil {
			_ = netlink.LinkDel(l)
			_ = netlink.LinkDel(peerLink)
			return errors.Wrapf(err, "failed to enable the link device: %v", peerLink)
		}
		log.FromContext(ctx).
			WithField("link.Name", peerLink.Attrs().Name).
			WithField("duration", time.Since(now)).
			WithField("netlink", "LinkSetUp").Debug("completed")

		// Store the link and peerLink
		peer.Store(ctx, isClient, peerLink)
	}
	return nil
}

func del(ctx context.Context, conn *networkservice.Connection, isClient bool) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		if peerLink, ok := peer.LoadAndDelete(ctx, isClient); ok {
			// Delete the peerLink which deletes all associated pair partners, routes, etc
			now := time.Now()
			if err := netlink.LinkDel(peerLink); err != nil {
				return errors.Wrapf(err, "failed to delete link device %v", peerLink)
			}
			log.FromContext(ctx).
				WithField("link.Name", peerLink.Attrs().Name).
				WithField("duration", time.Since(now)).
				WithField("netlink", "LinkDel").Debug("completed")
		}
		// Delete link from metadata
		link.Delete(ctx, isClient)
	}
	return nil
}
