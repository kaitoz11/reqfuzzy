package capture

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

func (c Capture) WriteRequests(directory string) (map[string]string, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve request directory: %w", err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create request directory: %w", err)
	}
	paths := make(map[string]string, len(c.Exchanges))
	for _, exchange := range c.Exchanges {
		if !safeRequestName(exchange.Name) || len(exchange.RequestRaw) == 0 {
			return nil, fmt.Errorf("unsafe or empty request %q", exchange.Name)
		}
		path := filepath.Join(root, exchange.Name+".txt")
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("request file %q is not a regular file", path)
			}
			stored, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read existing request %q: %w", path, err)
			}
			if !bytes.Equal(stored, exchange.RequestRaw) {
				return nil, fmt.Errorf("request file %q already exists with different content", path)
			}
			if err := os.Chmod(path, 0600); err != nil {
				return nil, fmt.Errorf("protect request file %q: %w", path, err)
			}
			paths[exchange.Name] = path
			continue
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect request file %q: %w", path, err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, fmt.Errorf("create request file %q: %w", path, err)
		}
		_, writeErr := file.Write(exchange.RequestRaw)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("write request file %q: %w", path, firstError(writeErr, closeErr))
		}
		paths[exchange.Name] = path
	}
	return paths, nil
}

func safeRequestName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func firstError(first, second error) error {
	if first != nil {
		return first
	}
	return second
}
