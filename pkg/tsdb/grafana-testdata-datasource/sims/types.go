package sims

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

type simulationKey struct {
	Type   string  `json:"type"`
	TickHZ float64 `json:"tick"`          // events/second
	UID    string  `json:"uid,omitempty"` // allows many instances of the same type
}

func (k simulationKey) String() string {
	hz := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", k.TickHZ), "0"), ".")
	if k.UID != "" {
		return fmt.Sprintf("%s/%shz/%s", k.Type, hz, k.UID)
	}
	return fmt.Sprintf("%s/%shz", k.Type, hz)
}

type simulationState struct {
	// Identify the simulation instance
	Key simulationKey `json:"key"`

	// Saved in panel options, and used to set initial values
	Config any `json:"config"`
}

type simulationInfo struct {
	Type         string      `json:"type"`
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	OnlyForward  bool        `json:"forward"`
	ConfigFields *data.Frame `json:"config"`

	// Create a simulation instance
	create func(q simulationState) (Simulation, error)
}

type Simulation interface {
	io.Closer
	GetState() simulationState
	SetConfig(vals map[string]any) error
	NewFrame(size int) *data.Frame
	GetValues(t time.Time) map[string]any
}

// checkedValueSim is implemented by simulations whose config can leave them
// unable to compute values. The config is read once per call, so the check
// and the computation always use the same values.
type checkedValueSim interface {
	getCheckedValues(t time.Time) (map[string]any, error)
}

func getSimValues(sim Simulation, t time.Time) (map[string]any, error) {
	if c, ok := sim.(checkedValueSim); ok {
		return c.getCheckedValues(t)
	}
	return sim.GetValues(t), nil
}
