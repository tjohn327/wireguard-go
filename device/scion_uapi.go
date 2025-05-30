/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"io"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/conn"
)

// SCION-specific UAPI operations and configurations

// handleScionUAPISet handles SCION-specific UAPI set operations
func (device *Device) handleScionUAPISet(key, value string) error {
	switch key {
	case "scion_path_policy":
		return device.setScionPathPolicy(value)
	case "scion_local_ia":
		return device.setScionLocalIA(value)
	case "scion_daemon_addr":
		return device.setScionDaemonAddr(value)	
	case "scion_query_paths":
		return device.queryScionPaths(value)
	default:
		return fmt.Errorf("unknown SCION UAPI key: %s", key)
	}
}

// setScionPathPolicy sets the SCION path selection policy
func (device *Device) setScionPathPolicy(value string) error {
	device.net.Lock()
	defer device.net.Unlock()

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		policy := conn.ParsePathPolicy(value)
		scionBind.SetPathPolicy(policy)
		device.log.Verbosef("Set SCION path policy to: %s", policy)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}


// setScionLocalIA sets the local IA for SCION
func (device *Device) setScionLocalIA(value string) error {
	device.net.Lock()
	defer device.net.Unlock()

	ia, err := addr.ParseIA(value)
	if err != nil {
		return fmt.Errorf("invalid IA format: %s", value)
	}

	// This would require recreating the bind, which is more complex
	// For now, just log the attempt
	device.log.Verbosef("Request to set SCION local IA to: %s (requires restart)", ia)
	return fmt.Errorf("changing local IA requires device restart")
}

// setScionDaemonAddr sets the SCION daemon address
func (device *Device) setScionDaemonAddr(value string) error {
	device.net.Lock()
	defer device.net.Unlock()

	// This would require recreating the bind connection
	device.log.Verbosef("Request to set SCION daemon address to: %s (requires restart)", value)
	return fmt.Errorf("changing daemon address requires device restart")
}


// queryScionPaths queries available paths to a destination IA (placeholder for now)
func (device *Device) queryScionPaths(value string) error {
	device.net.RLock()
	defer device.net.RUnlock()

	dstIA, err := addr.ParseIA(value)
	if err != nil {
		return fmt.Errorf("invalid destination IA: %s", value)
	}

	if _, ok := device.net.bind.(*conn.ScionNetBind); ok {
		device.log.Verbosef("Path query requested for %s (not implemented yet)", dstIA)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// writeScionUAPIStatus writes SCION-specific status to the UAPI
func (device *Device) writeScionUAPIStatus(buf io.Writer) {
	device.net.RLock()
	defer device.net.RUnlock()

	if _, ok := device.net.bind.(*conn.ScionNetBind); ok {
		fmt.Fprintf(buf, "scion_enabled=true\n")
	} else {
		fmt.Fprintf(buf, "scion_enabled=false\n")
	}
}

// Peer-specific SCION methods

// setScionPeerEndpoint sets a SCION endpoint for a peer
func (peer *Peer) setScionPeerEndpoint(value string) error {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	if scionBind, ok := peer.device.net.bind.(*conn.ScionNetBind); ok {
		endpoint, err := scionBind.ParseEndpoint(value)
		if err != nil {
			return fmt.Errorf("failed to parse SCION endpoint %s: %w", value, err)
		}

		peer.endpoint.val = endpoint
		peer.device.log.Verbosef("Set SCION endpoint for peer: %s", value)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// writeScionPeerStatus writes SCION-specific peer status
func (peer *Peer) writeScionPeerStatus(buf io.Writer) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	if scionEp, ok := peer.endpoint.val.(*conn.ScionNetEndpoint); ok {
		fmt.Fprintf(buf, "scion_endpoint=true\n")
		if scionAddr := scionEp.GetScionAddr(); scionAddr != nil {
			fmt.Fprintf(buf, "scion_address=%s\n", scionAddr.String())
		}
		
	} else {
		fmt.Fprintf(buf, "scion_endpoint=false\n")
	}
}

// Enhanced UAPI command parsing for SCION

// parseScionUAPILine parses a SCION-specific UAPI line
func parseScionUAPILine(line string) (key, value string, isScionCommand bool) {
	if !strings.HasPrefix(line, "scion_") {
		return "", "", false
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}
