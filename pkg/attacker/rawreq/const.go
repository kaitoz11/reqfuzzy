package rawreq

type ContextKey string

const (
	RequestBodyType ContextKey = "BodyType"
)

type BodyType int

const (
	None BodyType = iota
	Json
	FormData
	Xml
)
