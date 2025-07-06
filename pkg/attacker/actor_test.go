package attacker_test

import (
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"gopkg.in/yaml.v3"
)

func TestActor(t *testing.T) {
	yamlData := `username: testuser
password: testpass
metadata:
  role: admin
  otpsecret: mysecret
`
	actor := &attacker.Actor{}
	err := yaml.Unmarshal([]byte(yamlData), actor)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	if actor.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", actor.Username)
	}

	if actor.Password != "testpass" {
		t.Errorf("Expected password 'testpass', got '%s'", actor.Password)
	}

	if actor.Metadata["role"] != "admin" {
		t.Errorf("Expected role 'admin', got '%s'", actor.Metadata["role"])
	}

	if actor.Metadata["otpsecret"] != "mysecret" {
		t.Errorf("Expected otpsecret 'mysecret', got '%s'", actor.Metadata["otpsecret"])
	}
}
