// Demonstration of a simple unsafe way to do session-token based
// authentication. Users register with a username and password, then can log in
// with a username and password. The only page they can access is the root '/'
// page, and if they don't have a valid cookie of name 'auth', then they will
// be fed a 403 error.
package main

import (
	"bytes"
	"encoding/base64"
	_ "encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const loginstr string = `
<!DOCTYPE html>
<html>
<body>
    <div id="content">
<h1>%s</h1>
<form method="POST">
    <div>
        <label for="username">Username:</label>
        <input type="text" required name="username" id="username">
        <label for="password">Password</label>
        <input type="password" required name="password" id="password">
    </div>
    <div>
        <button>Submit login</button>
    </div>
</form>
    </div>
</body>
</html>
`

var logindata map[string]string

func register(w http.ResponseWriter, req *http.Request) {
	if strings.ToUpper(req.Method) == "GET" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, loginstr, "Register Account")
		return
	}
	if strings.ToUpper(req.Method) != "POST" {
		http.Error(w, "405 method not allowed, must be either POST or GET", http.StatusMethodNotAllowed)
		return
	}
	contents, _ := ioutil.ReadAll(req.Body)
	buf := bytes.NewBuffer(contents)
	req.Body = ioutil.NopCloser(buf)
	req.ParseForm()

	username := req.Form.Get("username")
	password := req.Form.Get("password")

	if _, ok := logindata[username]; ok {
		// Don't allow users to overwrite other users login creds
		http.Error(w, "403 incorrect credentials", http.StatusForbidden)
		return
	}
	logindata[username] = password

	authtoken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: authtoken, MaxAge: 9999999})
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, req *http.Request) {
	if strings.ToUpper(req.Method) == "GET" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, loginstr, "Log In")
		return
	}
	if strings.ToUpper(req.Method) != "POST" {
		http.Error(w, "405 method not allowed, must be either POST or GET", http.StatusMethodNotAllowed)
		return
	}
	contents, _ := ioutil.ReadAll(req.Body)
	buf := bytes.NewBuffer(contents)
	req.Body = ioutil.NopCloser(buf)
	req.ParseForm()

	username := req.Form.Get("username")
	password := req.Form.Get("password")

	var ok bool
	var storedpw string
	if storedpw, ok = logindata[username]; !ok || storedpw != password {
		http.Error(w, "403 incorrect credentials", http.StatusForbidden)
		return
	}

	authtoken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	// Equivalent to:
	//w.Header().Add("Set-Cookie", fmt.Sprintf("auth=%s; Max-Age=9999999", authtoken))
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: authtoken, MaxAge: 9999999})
	http.Redirect(w, req, "/", http.StatusSeeOther)
	return
}

func hello_world(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello world!\n")
	fmt.Fprintf(w, "%v", req.Cookies())
	fmt.Printf("%v\n", logindata)
}

func require_auth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		authcookie, err := req.Cookie("auth")
		if err != nil {
			panic(err)
		}
		decb, err := base64.StdEncoding.DecodeString(authcookie.Value)
		if err != nil {
			panic(err)
		}
		parts := strings.Split(string(decb), ":")
		username := parts[0]
		password := parts[1]
		var storedpw string
		var ok bool
		fmt.Printf("username: %s\n", username)
		fmt.Printf("password: %s\n", password)
		if storedpw, ok = logindata[username]; !ok || storedpw != password {
			http.Error(w, "403 incorrect credentials", http.StatusForbidden)
			return
		}
		// All good, continue
		handler(w, req)
	}
}

func main() {
	logindata = map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", require_auth(hello_world))
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/register", register)
	http.ListenAndServe(":8080", mux)
}
