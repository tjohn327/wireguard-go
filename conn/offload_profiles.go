/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"runtime"
	"sync"
	"time"
)

// OffloadCapabilities describes hardware offload support for a specific NIC
type OffloadCapabilities struct {
	// Basic capabilities
	SupportsTxOffload bool
	SupportsRxOffload bool

	// SCION-specific capabilities
	SupportsSCIONTxOffload bool
	SupportsSCIONRxOffload bool

	// Performance characteristics
	MaxSegmentSize     uint16
	RequiresAlignment  bool
	PreferredBatchSize int

	// Known issues and workarounds
	DisableTxOnLowSpeed bool // Disable TX offload on 1G or lower NICs
	DisableRxForSCION   bool // Disable RX offload for SCION due to performance issues
	RequiresFallback    bool // Requires fallback detection
}

// OffloadProfile contains NIC-specific optimization settings
type OffloadProfile struct {
	Name         string
	Vendor       string
	Device       string
	Capabilities OffloadCapabilities
	Description  string
}

// PerformanceMonitor tracks offload performance and triggers adaptations
type PerformanceMonitor struct {
	mu                sync.RWMutex
	enabled           bool
	measurementWindow time.Duration

	// Performance metrics
	txPacketsSuccess uint64
	txPacketsFailure uint64
	rxPacketsSuccess uint64
	rxPacketsFailure uint64

	// Timing metrics
	lastMeasurement time.Time
	avgTxLatency    time.Duration
	avgRxLatency    time.Duration

	// Adaptive thresholds
	failureThreshold float64
	latencyThreshold time.Duration
}

// AdaptiveOffloadManager manages hardware offload settings based on runtime performance
type AdaptiveOffloadManager struct {
	mu      sync.RWMutex
	profile *OffloadProfile
	monitor *PerformanceMonitor

	// Current settings
	txOffloadEnabled bool
	rxOffloadEnabled bool

	// Adaptation state
	adaptationEnabled  bool
	lastAdaptation     time.Time
	adaptationCooldown time.Duration

	// Fallback state
	inFallbackMode bool
	fallbackReason string
}

// Known NIC profiles with SCION-specific optimizations
var knownProfiles = map[string]OffloadProfile{
	// Intel NICs - generally good SCION support
	"intel_e1000e": {
		Name:   "Intel E1000E",
		Vendor: "Intel",
		Device: "e1000e",
		Capabilities: OffloadCapabilities{
			SupportsTxOffload:      true,
			SupportsRxOffload:      true,
			SupportsSCIONTxOffload: true,
			SupportsSCIONRxOffload: false, // Disabled due to performance issues
			MaxSegmentSize:         9000,
			RequiresAlignment:      false,
			PreferredBatchSize:     32,
			DisableTxOnLowSpeed:    true,
			DisableRxForSCION:      true,
			RequiresFallback:       true,
		},
		Description: "Intel Gigabit Ethernet - disable RX offload for SCION",
	},

	// Broadcom NICs - mixed support
	"broadcom_bnx2x": {
		Name:   "Broadcom NetXtreme II",
		Vendor: "Broadcom",
		Device: "bnx2x",
		Capabilities: OffloadCapabilities{
			SupportsTxOffload:      true,
			SupportsRxOffload:      true,
			SupportsSCIONTxOffload: false, // Poor SCION support
			SupportsSCIONRxOffload: false,
			MaxSegmentSize:         4096,
			RequiresAlignment:      true,
			PreferredBatchSize:     16,
			DisableTxOnLowSpeed:    true,
			DisableRxForSCION:      true,
			RequiresFallback:       true,
		},
		Description: "Broadcom NIC - disable all offloads for SCION",
	},

	// Realtek NICs - typically low performance, disable offloads
	"realtek_r8169": {
		Name:   "Realtek RTL8169",
		Vendor: "Realtek",
		Device: "r8169",
		Capabilities: OffloadCapabilities{
			SupportsTxOffload:      false,
			SupportsRxOffload:      false,
			SupportsSCIONTxOffload: false,
			SupportsSCIONRxOffload: false,
			MaxSegmentSize:         1500,
			RequiresAlignment:      false,
			PreferredBatchSize:     8,
			DisableTxOnLowSpeed:    true,
			DisableRxForSCION:      true,
			RequiresFallback:       false,
		},
		Description: "Realtek NIC - disable all offloads for optimal performance",
	},

	// Default profile for unknown NICs
	"default": {
		Name:   "Default Profile",
		Vendor: "Unknown",
		Device: "unknown",
		Capabilities: OffloadCapabilities{
			SupportsTxOffload:      true,
			SupportsRxOffload:      false, // Conservative default
			SupportsSCIONTxOffload: false, // Conservative for SCION
			SupportsSCIONRxOffload: false,
			MaxSegmentSize:         1500,
			RequiresAlignment:      false,
			PreferredBatchSize:     16,
			DisableTxOnLowSpeed:    true,
			DisableRxForSCION:      true,
			RequiresFallback:       true,
		},
		Description: "Conservative default profile for unknown NICs",
	},
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		enabled:           true,
		measurementWindow: 30 * time.Second,
		failureThreshold:  0.05, // 5% failure rate threshold
		latencyThreshold:  10 * time.Millisecond,
		lastMeasurement:   time.Now(),
	}
}

// NewAdaptiveOffloadManager creates a new adaptive offload manager
func NewAdaptiveOffloadManager(conn *net.UDPConn) *AdaptiveOffloadManager {
	profile := detectNICProfile(conn)

	return &AdaptiveOffloadManager{
		profile:            profile,
		monitor:            NewPerformanceMonitor(),
		adaptationEnabled:  true,
		adaptationCooldown: 60 * time.Second,

		// Initialize with profile defaults for SCION
		txOffloadEnabled: profile.Capabilities.SupportsSCIONTxOffload,
		rxOffloadEnabled: profile.Capabilities.SupportsSCIONRxOffload,
	}
}

// detectNICProfile attempts to detect the NIC type and return appropriate profile
func detectNICProfile(conn *net.UDPConn) *OffloadProfile {
	// On Linux, try to detect the network device
	if runtime.GOOS == "linux" {
		if deviceName := getLinuxNetworkDevice(conn); deviceName != "" {
			// Try to match known device patterns
			for _, profile := range knownProfiles {
				if matchesDevicePattern(deviceName, profile.Device) {
					profileCopy := profile // Create a copy to avoid reference issues
					return &profileCopy
				}
			}
		}
	}

	// Return default profile for unknown devices
	defaultProfile := knownProfiles["default"]
	return &defaultProfile
}

// matchesDevicePattern checks if a device name matches a profile pattern
func matchesDevicePattern(deviceName, pattern string) bool {
	// Simple pattern matching - could be enhanced with regex
	switch pattern {
	case "e1000e":
		return deviceName == "e1000e" || deviceName == "igb" || deviceName == "ixgbe"
	case "bnx2x":
		return deviceName == "bnx2x" || deviceName == "bnx2"
	case "r8169":
		return deviceName == "r8169" || deviceName == "r8168"
	default:
		return false
	}
}

// getLinuxNetworkDevice attempts to get the network device name on Linux
func getLinuxNetworkDevice(conn *net.UDPConn) string {
	// This is a simplified implementation
	// In practice, this would query /sys/class/net or use netlink
	// For now, return empty string to use default profile
	return ""
}

// RecordTxSuccess records a successful transmit operation
func (pm *PerformanceMonitor) RecordTxSuccess(latency time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.txPacketsSuccess++
	if latency > 0 {
		// Simple moving average for demonstration
		pm.avgTxLatency = (pm.avgTxLatency + latency) / 2
	}
}

// RecordTxFailure records a failed transmit operation
func (pm *PerformanceMonitor) RecordTxFailure() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.txPacketsFailure++
}

// RecordRxSuccess records a successful receive operation
func (pm *PerformanceMonitor) RecordRxSuccess(latency time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.rxPacketsSuccess++
	if latency > 0 {
		pm.avgRxLatency = (pm.avgRxLatency + latency) / 2
	}
}

// RecordRxFailure records a failed receive operation
func (pm *PerformanceMonitor) RecordRxFailure() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.rxPacketsFailure++
}

// ShouldAdaptOffloads checks if offload settings should be adapted based on performance
func (pm *PerformanceMonitor) ShouldAdaptOffloads() (shouldDisableTx, shouldDisableRx bool, reason string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return false, false, ""
	}

	// Check if enough time has passed for meaningful measurement
	if time.Since(pm.lastMeasurement) < pm.measurementWindow {
		return false, false, ""
	}

	totalTx := pm.txPacketsSuccess + pm.txPacketsFailure
	totalRx := pm.rxPacketsSuccess + pm.rxPacketsFailure

	// Check TX failure rate
	if totalTx > 100 { // Need minimum sample size
		txFailureRate := float64(pm.txPacketsFailure) / float64(totalTx)
		if txFailureRate > pm.failureThreshold {
			shouldDisableTx = true
			reason = "High TX failure rate"
		}
	}

	// Check RX failure rate
	if totalRx > 100 {
		rxFailureRate := float64(pm.rxPacketsFailure) / float64(totalRx)
		if rxFailureRate > pm.failureThreshold {
			shouldDisableRx = true
			if reason != "" {
				reason += ", High RX failure rate"
			} else {
				reason = "High RX failure rate"
			}
		}
	}

	// Check latency thresholds
	if pm.avgTxLatency > pm.latencyThreshold {
		shouldDisableTx = true
		if reason != "" {
			reason += ", High TX latency"
		} else {
			reason = "High TX latency"
		}
	}

	if pm.avgRxLatency > pm.latencyThreshold {
		shouldDisableRx = true
		if reason != "" {
			reason += ", High RX latency"
		} else {
			reason = "High RX latency"
		}
	}

	return shouldDisableTx, shouldDisableRx, reason
}

// GetOptimalSettings returns the optimal offload settings for the current conditions
func (aom *AdaptiveOffloadManager) GetOptimalSettings() (txOffload, rxOffload bool, batchSize int) {
	aom.mu.RLock()
	defer aom.mu.RUnlock()

	// Check if we're in fallback mode
	if aom.inFallbackMode {
		return false, false, 1 // Conservative fallback
	}

	// Check if adaptation is needed
	if aom.adaptationEnabled && time.Since(aom.lastAdaptation) > aom.adaptationCooldown {
		shouldDisableTx, shouldDisableRx, reason := aom.monitor.ShouldAdaptOffloads()

		if shouldDisableTx || shouldDisableRx {
			// Trigger adaptation
			go aom.triggerAdaptation(shouldDisableTx, shouldDisableRx, reason)
		}
	}

	return aom.txOffloadEnabled, aom.rxOffloadEnabled, aom.profile.Capabilities.PreferredBatchSize
}

// triggerAdaptation adapts the offload settings based on performance feedback
func (aom *AdaptiveOffloadManager) triggerAdaptation(disableTx, disableRx bool, reason string) {
	aom.mu.Lock()
	defer aom.mu.Unlock()

	if disableTx {
		aom.txOffloadEnabled = false
	}

	if disableRx {
		aom.rxOffloadEnabled = false
	}

	aom.lastAdaptation = time.Now()

	// Enter fallback mode if both are disabled
	if !aom.txOffloadEnabled && !aom.rxOffloadEnabled {
		aom.inFallbackMode = true
		aom.fallbackReason = reason
	}
}

// ResetMetrics resets performance monitoring metrics
func (aom *AdaptiveOffloadManager) ResetMetrics() {
	aom.monitor.mu.Lock()
	defer aom.monitor.mu.Unlock()

	aom.monitor.txPacketsSuccess = 0
	aom.monitor.txPacketsFailure = 0
	aom.monitor.rxPacketsSuccess = 0
	aom.monitor.rxPacketsFailure = 0
	aom.monitor.lastMeasurement = time.Now()
}

// GetProfile returns the current NIC profile
func (aom *AdaptiveOffloadManager) GetProfile() *OffloadProfile {
	aom.mu.RLock()
	defer aom.mu.RUnlock()
	return aom.profile
}

// GetStatus returns the current status of the adaptive offload manager
func (aom *AdaptiveOffloadManager) GetStatus() (txEnabled, rxEnabled, inFallback bool, reason string) {
	aom.mu.RLock()
	defer aom.mu.RUnlock()

	return aom.txOffloadEnabled, aom.rxOffloadEnabled, aom.inFallbackMode, aom.fallbackReason
}
