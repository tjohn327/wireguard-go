/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
)

const (
	DefaultSCIONDaemonAddr = "127.0.0.1:30255"
)

// LoadScionConfigFromEnv loads SCION configuration from environment variables
func LoadScionConfigFromEnv() (*ScionConfig, error) {
	config := &ScionConfig{
		DaemonAddr:   DefaultSCIONDaemonAddr,
		PathPolicy:   PathPolicyFirst,
	}

	// SCION daemon address
	if addr := os.Getenv("SCION_DAEMON_ADDRESS"); addr != "" {
		config.DaemonAddr = addr
	}

	// Local IA (ISD-AS)
	if iaStr := os.Getenv("SCION_LOCAL_IA"); iaStr != "" {
		parts := strings.Split(iaStr, ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid SCION_LOCAL_IA format %q: expected ISD-AS", iaStr)
		}
		ia, err := addr.ParseIA(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid SCION_LOCAL_IA %q: %w", iaStr, err)
		}
		local_IP := net.ParseIP(parts[1])
		if local_IP == nil {
			return nil, fmt.Errorf("invalid SCION_LOCAL_IA %q: %w", iaStr, err)
		}
		config.LocalIP = local_IP
		config.LocalIA = ia
	} else {
		return nil, fmt.Errorf("SCION_LOCAL_IA environment variable is required")
	}

	// Path policy
	if policy := os.Getenv("SCION_PATH_POLICY"); policy != "" {
		config.PathPolicy = ParsePathPolicy(policy)
	}

	return config, nil
}

// ValidateConfig validates the SCION configuration
func (c *ScionConfig) ValidateConfig() error {
	if c.LocalIA.IsZero() {
		return fmt.Errorf("LocalIA cannot be zero")
	}

	if c.DaemonAddr == "" {
		return fmt.Errorf("DaemonAddr cannot be empty")
	}

	return nil
}

// String returns a string representation of the configuration
func (c *ScionConfig) String() string {
	return fmt.Sprintf("ScionConfig{LocalIA: %s, DaemonAddr: %s, PathPolicy: %s}",
		c.LocalIA, c.DaemonAddr, c.PathPolicy)
}

// DefaultScionConfig returns a default SCION configuration
func DefaultScionConfig() *ScionConfig {
	return &ScionConfig{
		DaemonAddr:   DefaultSCIONDaemonAddr,
		PathPolicy:   PathPolicyFirst,
	}
}

// ParseIA parses an IA string in the format "ISD-AS"
func ParseIA(s string) (addr.IA, error) {
	return addr.ParseIA(s)
}

// FormatIA formats an IA to string
func FormatIA(ia addr.IA) string {
	return ia.String()
}

// Environment variable names for SCION configuration
const (
	EnvSCIONDaemonAddr   = "SCION_DAEMON_ADDRESS"
	EnvSCIONLocalIA      = "SCION_LOCAL_IA"
	EnvSCIONTopology     = "SCION_TOPOLOGY_FILE"
	EnvSCIONPathPolicy   = "SCION_PATH_POLICY"
)

// GetConfigSummary returns a summary of current SCION configuration
func GetConfigSummary() string {
	var parts []string

	if addr := os.Getenv(EnvSCIONDaemonAddr); addr != "" {
		parts = append(parts, fmt.Sprintf("DaemonAddr=%s", addr))
	}

	if ia := os.Getenv(EnvSCIONLocalIA); ia != "" {
		parts = append(parts, fmt.Sprintf("LocalIA=%s", ia))
	}

	if policy := os.Getenv(EnvSCIONPathPolicy); policy != "" {
		parts = append(parts, fmt.Sprintf("PathPolicy=%s", policy))
	}

	if len(parts) == 0 {
		return "No SCION configuration found"
	}

	return strings.Join(parts, ", ")
}
