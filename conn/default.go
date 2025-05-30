//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"os"
)

func NewDefaultBind() Bind {
	return NewDefaultBindWithLogger(nil)
}

func NewDefaultBindWithLogger(logger any) Bind {
	// Create a logger wrapper if needed
	var scionLogger Logger
	if logger != nil {
		// Handle the device.Logger struct type
		scionLogger = &LoggerWrapper{logger}
	}
	// Check if SCION is configured via environment variables
	if os.Getenv("SCION_LOCAL_IA") != "" {
		config, err := LoadScionConfigFromEnv()
		if err == nil && config != nil {
			if scionLogger != nil {
				scionLogger.Verbosef("Using SCION bind: %s", config.String())
			}
			return NewScionNetBind(config, scionLogger)
		}
		if scionLogger != nil {
			scionLogger.Errorf("Failed to load SCION config: %v, falling back to standard bind", err)
		}
	} 

	// Fallback to standard bind
	if scionLogger != nil {
		scionLogger.Verbosef("Using standard IP bind")
	}
	return NewStdNetBind()
}

// LoggerWrapper wraps device.Logger to implement our Logger interface
type LoggerWrapper struct {
	logger any
}

func (w *LoggerWrapper) Verbosef(format string, args ...interface{}) {
	fmt.Printf("Verbosef: %s %v\n", format, args)
	if w.logger == nil {
		return
	}
	// Handle device.Logger struct
	if deviceLogger, ok := w.logger.(struct {
		Verbosef func(format string, args ...interface{})
		Errorf   func(format string, args ...interface{})
	}); ok && deviceLogger.Verbosef != nil {
		deviceLogger.Verbosef(format, args...)
	}
}

func (w *LoggerWrapper) Errorf(format string, args ...interface{}) {
	fmt.Printf("Errorf: %s %v\n", format, args)
	if w.logger == nil {
		return
	}
	// Handle device.Logger struct
	if deviceLogger, ok := w.logger.(struct {
		Verbosef func(format string, args ...interface{})
		Errorf   func(format string, args ...interface{})
	}); ok && deviceLogger.Errorf != nil {
		deviceLogger.Errorf(format, args...)
	}
}

func NewScionBind(config *ScionConfig, logger Logger) Bind {
	return NewScionNetBind(config, logger)
}

func NewStandardBind() Bind {
	return NewStdNetBind()
}
