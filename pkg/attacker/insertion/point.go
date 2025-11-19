package insertion

import "slices"

type InsertionPoint struct {
	From RequestPart
	Type InsertionPointType
	Identifier string
}

type RequestPart int

const (
	UrlRequestPart RequestPart = iota
	HeaderRequestPart
	BodyRequestPart
)

type InsertionPointType int

const (
	UrlPathInsertPoint InsertionPointType = iota
	UrlQueryInsertPoint
	HeaderInsertPoint
	BodyJsonInsertPoint
	BodyFormInsertPoint
	BodyRawInsertPoint
	BodyUrlEncodedInsertPoint
)

func (rp RequestPart) Has() []InsertionPointType {
	switch rp {
	case UrlRequestPart:
		return []InsertionPointType{UrlPathInsertPoint, UrlQueryInsertPoint}
	case HeaderRequestPart:
		return []InsertionPointType{HeaderInsertPoint}
	case BodyRequestPart:
		return []InsertionPointType{BodyJsonInsertPoint, BodyFormInsertPoint, BodyRawInsertPoint, BodyUrlEncodedInsertPoint}
	}
	return []InsertionPointType{}
}

func (ipt InsertionPointType) IsIn(rp RequestPart) bool {
	return slices.Contains(rp.Has(), ipt)
}
