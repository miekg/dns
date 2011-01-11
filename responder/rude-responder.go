package responder

import (
	"./types"
)

func Respond(query types.DNSquery, config map[string]interface{}) types.DNSresponse {
	var (
		result types.DNSresponse
	)
	result.Responsecode = types.REFUSED
	return result
}

func Init(firstoption int) {
}
