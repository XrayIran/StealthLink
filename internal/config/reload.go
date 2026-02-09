package config

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

// ReloadableConfig provides hot-reload capabilities for configuration.
// It watches the config file for changes and atomically updates the
// configuration without dropping existing sessions.
type ReloadableConfig struct {
	path      string
	current   atomic.Value // *Config
	mu        sync.RWMutex
	watchers  []func(old, new *Config)
	watcher   *fsnotify.Watcher
	stopCh    chan struct{}
	reloading int32 // atomic flag to prevent concurrent reloads
}

// NewReloadable creates a new reloadable config manager.
func NewReloadable(path string) (*ReloadableConfig, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, fmt.Errorf("initial config load: %w", err)
	}

	r := &ReloadableConfig{
		path:   path,
		stopCh: make(chan struct{}),
	}
	r.current.Store(cfg)

	// Setup file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch config file: %w", err)
	}

	r.watcher = watcher
	go r.watchLoop()

	return r, nil
}

// Get returns the current configuration.
func (r *ReloadableConfig) Get() *Config {
	return r.current.Load().(*Config)
}

// Watch registers a callback to be called when config changes.
// The callback receives both the old and new configurations.
func (r *ReloadableConfig) Watch(fn func(old, new *Config)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.watchers = append(r.watchers, fn)
}

// Reload forces a config reload from disk.
func (r *ReloadableConfig) Reload() error {
	// Prevent concurrent reloads
	if !atomic.CompareAndSwapInt32(&r.reloading, 0, 1) {
		return fmt.Errorf("reload already in progress")
	}
	defer atomic.StoreInt32(&r.reloading, 0)

	// Load new config
	newCfg, err := Load(r.path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Validate transition
	oldCfg := r.Get()
	if err := r.validateTransition(oldCfg, newCfg); err != nil {
		return fmt.Errorf("validate transition: %w", err)
	}

	// Atomically swap configs
	r.current.Store(newCfg)

	// Notify watchers
	r.mu.RLock()
	watchers := make([]func(old, new *Config), len(r.watchers))
	copy(watchers, r.watchers)
	r.mu.RUnlock()

	for _, fn := range watchers {
		go fn(oldCfg, newCfg)
	}

	return nil
}

// validateTransition checks if the config change is allowed.
// Some changes (like role change) require a restart.
func (r *ReloadableConfig) validateTransition(old, new *Config) error {
	// Role cannot be changed without restart
	if old.Role != new.Role {
		return fmt.Errorf("role change requires restart: %s -> %s", old.Role, new.Role)
	}

	// Gateway listen address cannot be changed without restart
	if old.Role == "gateway" && old.Gateway.Listen != new.Gateway.Listen {
		return fmt.Errorf("gateway listen address change requires restart")
	}

	// Agent ID cannot be changed
	if old.Role == "agent" && old.Agent.ID != new.Agent.ID {
		return fmt.Errorf("agent ID change requires restart")
	}

	// Shared key cannot be changed without restart (would break existing sessions)
	if old.Security.SharedKey != new.Security.SharedKey {
		return fmt.Errorf("shared key change requires restart")
	}

	return nil
}

// watchLoop monitors the config file for changes.
func (r *ReloadableConfig) watchLoop() {
	for {
		select {
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				// Config file modified, reload it
				if err := r.Reload(); err != nil {
					// Log error but don't crash
					fmt.Fprintf(os.Stderr, "config reload failed: %v\n", err)
				}
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "config watcher error: %v\n", err)
		case <-r.stopCh:
			return
		}
	}
}

// Close stops the file watcher.
func (r *ReloadableConfig) Close() error {
	close(r.stopCh)
	return r.watcher.Close()
}

// ConfigReloader interface for components that support hot reload.
type ConfigReloader interface {
	OnConfigReload(old, new *Config)
}

// ServiceReloader handles graceful service updates on config reload.
type ServiceReloader struct {
	mu       sync.RWMutex
	services map[string]ServiceHandler
}

// ServiceHandler manages a single service.
type ServiceHandler interface {
	UpdateConfig(svc Service) error
	Stop() error
}

// NewServiceReloader creates a new service reloader.
func NewServiceReloader() *ServiceReloader {
	return &ServiceReloader{
		services: make(map[string]ServiceHandler),
	}
}

// Register registers a service handler.
func (sr *ServiceReloader) Register(name string, handler ServiceHandler) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.services[name] = handler
}

// Unregister removes a service handler.
func (sr *ServiceReloader) Unregister(name string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	delete(sr.services, name)
}

// ReloadServices updates all services based on new config.
func (sr *ServiceReloader) ReloadServices(oldCfg, newCfg *Config) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	// Build map of new services
	newServices := make(map[string]Service)
	for _, svc := range newCfg.Services {
		newServices[svc.Name] = svc
	}

	// Update existing services
	for name, handler := range sr.services {
		if newSvc, ok := newServices[name]; ok {
			// Service exists, update it
			if err := handler.UpdateConfig(newSvc); err != nil {
				fmt.Fprintf(os.Stderr, "failed to update service %s: %v\n", name, err)
			}
		} else {
			// Service removed, stop it
			if err := handler.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to stop service %s: %v\n", name, err)
			}
		}
	}

	// Note: New services would be started by the main application loop
	// checking for services not in sr.services
}
