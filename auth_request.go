package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
)

type Ticket struct {
	Principal string
	Expiry    time.Time
}

func (t *Ticket) MarshalJSON() ([]byte, error) {

	return []byte(fmt.Sprintf(`{"Principal": "%s", "Expiry": %d}`, t.Principal, t.Expiry.Unix())), nil

}

func (t *Ticket) UnmarshalJSON(b []byte) error {

	type RawTicket struct {
		Principal string
		Expiry    int64
	}

	rt := &RawTicket{}
	json.Unmarshal(b, rt)

	t.Principal = rt.Principal
	t.Expiry = time.Unix(rt.Expiry, 0)

	return nil

}

func (t Ticket) isValid() bool {

	return t.Principal != "" && t.Expiry.After(time.Now())

}

func (t *Ticket) ValidateAndDecrypt(s string) {

	ciphertext, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}

	plaintext, err := DecryptWithMAC(ciphertext, ticketConfig.SecretKey)
	if err != nil {
		return
	}

	json.Unmarshal(plaintext, t)
}

func (t *Ticket) EncryptAndSign() string {

	plaintext, err := json.Marshal(t)
	if err != nil {
		fmt.Println(err)
	}

	nonce, err := Generate64BitNonce()
	if err != nil {
		return ""
	}

	ciphertext, err := EncryptThenMAC(plaintext, ticketConfig.SecretKey, nonce)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(ciphertext)

}

// Interface to hash password string
// into something stored in config.json
// this should be re-written later to use pbkdf
// or scrypt...
func passwordHash(password string) string {

	h := sha256.New()
	h.Write([]byte(password))

	s := hex.EncodeToString(h.Sum(nil))

	return s

}

func authenticate(username string, password string) bool {
	res, err := ticketConfig.AuthenticatePrincipal(username, passwordHash(password))
	if err != nil {
		return false
	}
	return res
}

func createPrincipalTicket(principal string, expiry time.Time) Ticket {
	return Ticket{
		Principal: principal,
		Expiry:    expiry,
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {

	// If cookie is set, check validity
	c, err := r.Cookie("ticket")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Valid ticket + principal has permission to
	// access the requested resource?
	tkt := &Ticket{}
	tkt.ValidateAndDecrypt(c.Value)

	resource := r.Header.Get("X-Original-URI")

	if tkt.isValid() {
		allowed := ticketConfig.PrincipalIsAuthorized(tkt.Principal, resource)
		if allowed {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	nsredirect, err := r.Cookie("NSREDIRECT")
	if err != nil {
		nsredirect = &http.Cookie{
			Name:    "NSREDIRECT",
			Value:   "/",
			Expires: time.Now().Add(time.Hour),
		}
	}

	if r.Method == http.MethodPost {

		username, password := r.FormValue("username"), r.FormValue("password")

		csrf := r.FormValue("csrf_token")
		csrfTkt := &Ticket{}
		csrfTkt.ValidateAndDecrypt(csrf)

		if authenticate(username, password) && csrfTkt.isValid() {

			tkt := createPrincipalTicket(username, time.Now().Add(time.Hour))
			c := &http.Cookie{
				Name:    "ticket",
				Value:   tkt.EncryptAndSign(),
				Expires: time.Now().Add(time.Hour * 24),
				Path:    "/",
			}

			http.SetCookie(w, c)
			http.Redirect(w, r, nsredirect.Value, http.StatusFound)

			return
		}
	}

	type Info struct {
		Page string
		CSRF string
	}

	t, err := template.ParseFiles("login.html")
	if err != nil {
		fmt.Println(err)
	}

	csrf := createPrincipalTicket("CSRFTOKEN", time.Now().Add(time.Minute*15))
	context := Info{Page: nsredirect.Value}
	context.CSRF = csrf.EncryptAndSign()

	t.Execute(w, context)

}

var ticketConfig Config

func main() {

	ticketConfig.Read("config.json")

	t := &Ticket{
		Principal: "ian",
		Expiry:    time.Now(),
	}

	t.EncryptAndSign()

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/_auth", authHandler)

	log.Fatal(http.ListenAndServe(":"+fmt.Sprint(ticketConfig.Port), nil))

}
