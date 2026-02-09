package ca

import (
	"sync"

	"github.com/go-logr/logr"
)

// Provider provides thread-safe access to the current CA certificate.
// It allows dynamic updates when the CA secret changes.
type Provider struct {
	mu        sync.RWMutex
	ca        *CA
	callbacks []func(*CA)
	log       logr.Logger
}

// NewProvider creates a new CA provider with an optional initial CA.
func NewProvider(initialCA *CA, log logr.Logger) *Provider {
	return &Provider{
		ca:  initialCA,
		log: log,
	}
}

// Get returns the current CA. Returns nil if no CA is loaded.
func (p *Provider) Get() *CA {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ca
}

// Update sets a new CA and notifies all registered callbacks.
func (p *Provider) Update(ca *CA) {
	p.mu.Lock()
	oldCA := p.ca
	p.ca = ca
	callbacks := p.callbacks
	p.mu.Unlock()

	if oldCA == nil || (ca != nil && string(oldCA.CertPEM) != string(ca.CertPEM)) {
		p.log.Info("CA updated", "cn", ca.Cert.Subject.CommonName)
		for _, cb := range callbacks {
			cb(ca)
		}
	}
}

// OnChange registers a callback that is called whenever the CA changes.
func (p *Provider) OnChange(fn func(*CA)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callbacks = append(p.callbacks, fn)
}

// GetCertPEM returns the current CA certificate PEM bytes.
// Returns nil if no CA is loaded.
func (p *Provider) GetCertPEM() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.ca == nil {
		return nil
	}
	return p.ca.CertPEM
}
