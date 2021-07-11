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
	if strings.ToLower(req.Method) != "get" {
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}
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

func main() {
	urls = map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect/", redirect)
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/list", func(w http.ResponseWriter, req *http.Request) {
		b, _ := json.Marshal(urls)
		w.Write(b)
	})
	http.ListenAndServe(":8080", mux)
}
