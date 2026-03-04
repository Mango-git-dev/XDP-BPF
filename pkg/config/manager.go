package config

import (
	"time"
)

type ProtectionStage uint32

const (
	StageAuto      ProtectionStage = 0
	StageRateLimit ProtectionStage = 1
	StageDPI       ProtectionStage = 2
	StageChallenge ProtectionStage = 3
)

type Manager struct {
	CurrentStage ProtectionStage
	IsLocked     bool
	LastPPS      uint64
	LastChange   time.Time
}

func NewManager() *Manager {
	return &Manager{
		CurrentStage: StageAuto,
		IsLocked:     false,
		LastChange:   time.Now(),
	}
}

// auto-pilot stage logic
func (m *Manager) CalculateAutoStage(pps uint64) ProtectionStage {
	if m.IsLocked {
		return m.CurrentStage
	}

	m.LastPPS = pps

	// pps thresholds
	var targetStage ProtectionStage
	switch {
	case pps > 50000:
		targetStage = StageChallenge
	case pps > 10000:
		targetStage = StageDPI
	case pps > 2000:
		targetStage = StageRateLimit
	default:
		targetStage = StageAuto
	}

	// cooldown hạ stage
	if targetStage < m.CurrentStage {
		if time.Since(m.LastChange) > 15*time.Second {
			m.CurrentStage = targetStage
			m.LastChange = time.Now()
		}
	} else if targetStage > m.CurrentStage {
		// escalate immediately
		m.CurrentStage = targetStage
		m.LastChange = time.Now()
	}

	return m.CurrentStage
}

func (m *Manager) LockStage(s ProtectionStage) {
	m.CurrentStage = s
	m.IsLocked = (s != StageAuto)
	m.LastChange = time.Now()
}
