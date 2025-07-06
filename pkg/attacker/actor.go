package attacker

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Actor struct {
	Username string            `yaml:"username"`
	Password string            `yaml:"password"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

func (a *Actor) GetMetadata(key string) string {
	if value, exists := a.Metadata[key]; exists {
		return value
	}
	return ""
}

func (a *Actor) SetMetadata(key, value string) {
	if a.Metadata == nil {
		a.Metadata = make(map[string]string)
	}
	a.Metadata[key] = value
}

func (a *Actor) UpdatePassword(newPass string) {
	if a.Password != newPass {
		a.Password = newPass
	}
}

func (a *Actor) UpdateUsername(newUser string) {
	if a.Username != newUser {
		a.Username = newUser
	}
}

type ActorRoom struct {
	Actors []*Actor `yaml:"room"`
}

func (ar *ActorRoom) AddActor(actor Actor) {
	ar.Actors = append(ar.Actors, &actor)
}

func (ar *ActorRoom) RemoveActor(username string) {
	for i, actor := range ar.Actors {
		if actor.Username == username {
			ar.Actors = append(ar.Actors[:i], ar.Actors[i+1:]...)
			return
		}
	}
}

func (ar *ActorRoom) GetActor(username string) (*Actor, error) {
	for _, actor := range ar.Actors {
		if actor.Username == username {
			return actor, nil
		}
	}
	return nil, fmt.Errorf("actor with username %s not found", username)
}

func LoadCreadentialsFromYAMLFile(filePath string) (*ActorRoom, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("file %s is empty", filePath)

	}

	var room ActorRoom
	if err := yaml.Unmarshal(data, &room); err != nil {
		return nil, err
	}
	return &room, nil
}

func SaveCredentialsToYAMLFile(filePath string, room *ActorRoom) error {
	data, err := yaml.Marshal(room)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}
	return nil
}
