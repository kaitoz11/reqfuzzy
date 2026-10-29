package flow

type Flow struct {
	Name  string `yaml:"name"`
	Steps []Step `yaml:"steps"`
}

type Step struct {
	ID            string       `yaml:"id"`
	Request       string       `yaml:"request"`
	Actor         string       `yaml:"actor,omitempty"`
	Bind          []Binding    `yaml:"bind,omitempty"`
	Extract       []Extraction `yaml:"extract,omitempty"`
	BeforeSend    string       `yaml:"before_send,omitempty"`
	AfterResponse string       `yaml:"after_response,omitempty"`
	Provides      []string     `yaml:"provides,omitempty"`
	ExpectStatus  *int         `yaml:"expect_status,omitempty"`
}

type Binding struct {
	Location string `yaml:"location"`
	Path     string `yaml:"path"`
	Variable string `yaml:"variable"`
	Prefix   string `yaml:"prefix,omitempty"`
}

type Extraction struct {
	Name     string `yaml:"name"`
	JSONPath string `yaml:"json,omitempty"`
	Cookie   string `yaml:"cookie,omitempty"`
}

// Value carries both the printable value and its exact JSON representation.
// JSON bindings use RawJSON to preserve numeric precision and scalar type.
type Value struct {
	RawJSON []byte
	Text    string
}

type Variables map[string]Value
