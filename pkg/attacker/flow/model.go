package flow

type Flow struct {
	Name  string `yaml:"name"`
	Steps []Step `yaml:"steps"`
}

type Step struct {
	ID           string       `yaml:"id"`
	Request      string       `yaml:"request"`
	Actor        string       `yaml:"actor"`
	Bind         []Binding    `yaml:"bind"`
	Extract      []Extraction `yaml:"extract"`
	BeforeSend   string       `yaml:"before_send"`
	ExpectStatus *int         `yaml:"expect_status"`
}

type Binding struct {
	Location string `yaml:"location"`
	Path     string `yaml:"path"`
	Variable string `yaml:"variable"`
	Prefix   string `yaml:"prefix,omitempty"`
}

type Extraction struct {
	Name     string `yaml:"name"`
	JSONPath string `yaml:"json"`
}

// Value carries both the printable value and its exact JSON representation.
// JSON bindings use RawJSON to preserve numeric precision and scalar type.
type Value struct {
	RawJSON []byte
	Text    string
}

type Variables map[string]Value
