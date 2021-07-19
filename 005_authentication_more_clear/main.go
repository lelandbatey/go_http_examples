// Demonstration of slightly more involved and slightly less insecure cookie
// based session-token authentication. Users register with a username and
// password, then can log in with a username and password. The only page they
// can access is the root '/' page, and if they don't have a valid cookie of
// name 'auth', then they will be fed a 403 error.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
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
	hashedpwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	fmt.Printf("register, username: %q, password: %q, hashedpwd: %q\n", username, password, string(hashedpwd))

	logindata[username] = string(hashedpwd)

	authtoken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, string(hashedpwd))))
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: authtoken, MaxAge: 99999999})
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

	fmt.Printf("login, username: %q, password: %q\n", username, password)

	var ok bool = true
	var storedpw string
	if storedpw, ok = logindata[username]; !ok {
		fmt.Printf("login, username %q not present\n", username)
		http.Error(w, "403 incorrect credentials", http.StatusForbidden)
		return
	}
	// We can't directly == compare hashed passwords as hashing the same text
	// twice doesn't yield the same hash. However, bcrypt can figure out if a
	// given text _could_ hash to a given hash, but to check that we must use
	// the CompareHashAndPassword() func.
	if err := bcrypt.CompareHashAndPassword([]byte(storedpw), []byte(password)); err != nil {
		fmt.Printf("login, comparehashandpassword says not equal %q %q\n", storedpw, password)
		http.Error(w, "403 incorrect credentials", http.StatusForbidden)
		return
	}

	atoken := AuthToken{Username: username, HashedPassword: string(storedpw)}
	// Equivalent to:
	//w.Header().Add("Set-Cookie", fmt.Sprintf("auth=%s; Max-Age=99999999", authtoken))
	http.SetCookie(w, NewCookieFromAuthToken(atoken))
	http.Redirect(w, req, "/", http.StatusSeeOther)
	return
}

func hello_world(w http.ResponseWriter, req *http.Request) {
	authcookie, err := req.Cookie("auth")
	if err != nil {
		panic(err)
	}
	atoken, err := NewAuthTokenFromCookie(authcookie.Value)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "Hello %s!\n", atoken.Username)
	fmt.Fprintf(w, "%v\n", req.Cookies())
	fmt.Fprintf(w, "decoded auth token: %s\n", atoken)
}

func require_auth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		authcookie, err := req.Cookie("auth")
		if err != nil {
			http.Error(w, "403 incorrect credentials", http.StatusForbidden)
			return
		}
		atoken, err := NewAuthTokenFromCookie(authcookie.Value)
		if err != nil {
			http.Error(w, "403 incorrect credentials", http.StatusForbidden)
			return
		}
		var storedpw string
		var ok bool
		fmt.Printf("require_auth, username: %q, hashedpwd: %q\n", atoken.Username, atoken.HashedPassword)
		if storedpw, ok = logindata[atoken.Username]; !ok || storedpw != atoken.HashedPassword {
			http.Error(w, "403 incorrect credentials", http.StatusForbidden)
			return
		}
		// All good, continue
		handler(w, req)
	}
}

type AuthToken struct {
	Username       string `json:"username"`
	HashedPassword string `json:"password"`
}

func (atoken AuthToken) String() string {
	atokb, _ := json.Marshal(atoken)
	return string(atokb)
}

func NewAuthTokenFromCookie(authcookie string) (AuthToken, error) {
	decb, err := base64.StdEncoding.DecodeString(authcookie)
	if err != nil {
		return AuthToken{}, err
	}
	parts := strings.Split(string(decb), ":")
	if len(parts) > 2 {
		return AuthToken{}, fmt.Errorf("cannot safely determine username and password from base64 "+
			"decoded cookie, more than 2 parts found when splitting on ':' char: %v", parts)
	}
	username := parts[0]
	password := parts[1]
	//fmt.Printf("%v %v\n", username, password)
	return AuthToken{Username: username, HashedPassword: password}, nil
}

func NewCookieFromAuthToken(atoken AuthToken) *http.Cookie {
	encodedtoken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", atoken.Username, atoken.HashedPassword)))
	return &http.Cookie{Name: "auth", Value: encodedtoken, MaxAge: 99999999}
}

func main() {
	logindata = map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", require_auth(hello_world))
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/register", register)
	http.ListenAndServe(":8080", mux)
}
