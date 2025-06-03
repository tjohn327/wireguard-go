/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
)

// SCION-specific UAPI operations and configurations

// handleScionUAPISet handles SCION-specific UAPI set operations
func (device *Device) handleScionUAPISet(key, value string) error {
	switch key {
	case "scion_path_policy":
		return device.setScionPathPolicy(value)
	case "scion_query_paths":
		return device.queryScionPaths(value)
	case "scion_set_path":
		return device.setScionPath(value)
	default:
		return fmt.Errorf("unknown SCION UAPI key: %s", key)
	}
}

// setScionPathPolicy sets the SCION path selection policy
func (device *Device) setScionPathPolicy(value string) error {
	device.net.Lock()
	defer device.net.Unlock()

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		scionBind.SetPathPolicy(value)
		device.log.Verbosef("Set SCION path policy to: %s", value)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// setScionPath sets a specific path for a destination IA
func (device *Device) setScionPath(value string) error {
	device.net.RLock()
	defer device.net.RUnlock()

	// Expected format: "IA:path_index" (e.g., "1-105:2")
	parts := strings.Split(value, "#")
	if len(parts) != 2 {
		return fmt.Errorf("invalid path selection format, expected 'IA:path_index'")
	}

	iaStr := parts[0]
	pathIndex, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid path index: %w", err)
	}

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		if err := scionBind.SetPath(iaStr, pathIndex); err != nil {
			return fmt.Errorf("failed to set path: %w", err)
		}
		device.log.Verbosef("Set SCION path for %s to index %d", iaStr, pathIndex)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// queryScionPaths queries available paths to a destination IA
func (device *Device) queryScionPaths(value string) error {
	device.net.RLock()
	defer device.net.RUnlock()

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		jsonStr, err := scionBind.GetPathsJSON(value)
		if err != nil {
			return fmt.Errorf("failed to get paths: %w", err)
		}
		device.log.Verbosef("Retrieved paths for %s", value)
		// Write the JSON response to the log since we can't write directly to UAPI
		device.log.Verbosef("SCION paths for %s: %s", value, jsonStr)
		return nil
	}

	return fmt.Errorf("SCION bind not available")
}

// writeScionUAPIStatus writes SCION-specific status to the UAPI
func (device *Device) writeScionUAPIStatus(buf io.Writer) {
	device.net.RLock()
	defer device.net.RUnlock()

	if scionBind, ok := device.net.bind.(*conn.ScionNetBind); ok {
		fmt.Fprintf(buf, "scion_enabled=true\n")
		// Add current path policy
		fmt.Fprintf(buf, "scion_path_policy=%s\n", scionBind.GetPathPolicy())
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
