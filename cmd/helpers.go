package main

import (
	"net/http"
	"net/http/httputil"
)

func dumpRequestShort(req *http.Request, body bool) (dump []byte) {
	if req != nil {
		dump, _ = httputil.DumpRequest(req, body)
	}
	return
}
