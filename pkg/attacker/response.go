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
