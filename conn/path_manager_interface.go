// Path Manager Interface for SCION
// This interface allows for different implementations of path management

package conn

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// PathManagerInterface defines the interface for SCION path management
type PathManagerInterface interface {
	// Core path management methods
	RegisterEndpoint(ia addr.IA)
	GetPath(ia addr.IA) (snet.Path, error)
	SetPolicy(policy string)
	Close()
	
	// HTTP API methods
	GetPathsJSON(iaStr string) (string, error)
	SetPath(iaStr string, pathIndex int) error
	GetPathPolicy() string
}