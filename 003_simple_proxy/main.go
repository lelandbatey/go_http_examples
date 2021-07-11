package main

import (
	//"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"

	//"io/ioutil"
	"net/http"
	"strings"
)

// RequireMethod allows us to add logic to an existing http.HandlerFunc so that
// it MUST be visited with a specific HTTP method.
func RequireMethod(m string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if strings.ToLower(req.Method) != strings.ToLower(m) {
			http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, req)
	}
}

type _Request struct {
	*http.Request
	GetBody interface{}
	Cancel  interface{}
}

func proxy(w http.ResponseWriter, req *http.Request) {
	b, _ := json.Marshal(_Request{Request: req})
	fmt.Printf("%s\n", string(b))
	desturl := req.URL.Path
	desturl = strings.TrimPrefix(desturl, "/")
	desturl = strings.TrimPrefix(desturl, "proxy/")
	if req.URL.RawQuery != "" {
		desturl = fmt.Sprintf("%s?%s", desturl, req.URL.RawQuery)
	}
	newreq, err := http.NewRequest(req.Method, desturl, req.Body)
	if err != nil {
		panic(err)
	}
	for key, headers := range req.Header {
		for _, header := range headers {
			newreq.Header.Add(key, header)
		}
	}
	resp, err := http.DefaultClient.Do(newreq)
	if err != nil {
		panic(err)
	}

	for key, headers := range resp.Header {
		for _, header := range headers {
			w.Header().Add(key, header)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		panic(err)
	}
}

func main() {
	http.ListenAndServe(":8080", http.HandlerFunc(proxy))
}
