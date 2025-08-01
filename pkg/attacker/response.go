package attacker

import (
	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
)

type Response struct {
	*req.Response
}

func (resp Response) GetJsonStringField(path string) string {
	result := gjson.Get(resp.String(), path)
	return result.String()
}

func (resp Response) GetJsonStringArrayField(path string) (ret []string) {
	result := gjson.Get(resp.String(), path)
	for _, item := range result.Array() {
		ret = append(ret, item.String())
	}
	return ret
}

func (resp Response) GetJsonIntField(path string) int64 {
	result := gjson.Get(resp.String(), path)
	return result.Int()
}

func (resp Response) GetJsonFloatField(path string) float64 {
	result := gjson.Get(resp.String(), path)
	return result.Float()
}

func (resp Response) GetJsonBoolField(path string) bool {
	result := gjson.Get(resp.String(), path)
	return result.Bool()
}

func (resp Response) GetJsonField(path string) gjson.Result {
	return gjson.Get(resp.String(), path)
}
