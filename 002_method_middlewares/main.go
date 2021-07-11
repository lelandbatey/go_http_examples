package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// A global variable in which we'll store the map of source keys to destination
// URLs
var urls map[string]string

func redirect(w http.ResponseWriter, req *http.Request) {
	redirectkey := strings.Join(strings.Split(req.URL.Path, "/")[2:], "/")
	dest, ok := urls[redirectkey]
	if !ok {
		http.Error(w, "404 no url registered for key "+redirectkey, http.StatusNotFound)
		return
	}
	http.Redirect(w, req, dest, http.StatusSeeOther)
}

func register(w http.ResponseWriter, req *http.Request) {
	contents, _ := ioutil.ReadAll(req.Body)
	h := sha1.Sum(contents)
	key := fmt.Sprintf("%x", h[:5])
	urls[key] = string(contents)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, fmt.Sprintf("Redirect for given URL %q at:\n%s://%s/redirect/%s", string(contents), "http", req.Host, key))
}

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

func main() {
	urls = map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect/", RequireMethod("GET", redirect))
	mux.HandleFunc("/register", RequireMethod("POST", register))
	mux.HandleFunc("/list", RequireMethod("GET", func(w http.ResponseWriter, req *http.Request) {
		b, _ := json.Marshal(urls)
		w.Write(b)
	}))
	http.ListenAndServe(":8080", mux)
}
