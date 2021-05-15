package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

type Ticket struct {
	principal string
	expiry    time.Time
}

func (t Ticket) isValid() bool {

	return t.principal != "" && t.expiry.After(time.Now())

}

func (t *Ticket) parseCookieValue(s string) {

	split := strings.Split(s, "|")
	if len(split) != 3 {
		return
	}

	expiry := time.Time{}

	principal := split[0]
	mac, _ := hex.DecodeString(split[2])

	expiryb, _ := hex.DecodeString(split[1])
	expiry.GobDecode(expiryb)

	tovalidate := Ticket{principal: principal, expiry: expiry}
	mac_v := tovalidate.getMAC()

	if hmac.Equal(mac, mac_v) {
		t.principal = principal
		t.expiry = expiry
	}

}

func (t Ticket) getMAC() []byte {

	h := hmac.New(sha256.New, ticketConfig.SecretKey)

	expiry, err := t.expiry.GobEncode()
	if err != nil {
		fmt.Println(error(err))
	}

	h.Write([]byte(t.principal))
	h.Write(expiry)

	mac := h.Sum(nil)
	return mac
}

func (t Ticket) createCookieValue() string {

	mac := t.getMAC()
	expiry, _ := t.expiry.GobEncode()

	return fmt.Sprintf("%s|%s|%s", t.principal, hex.EncodeToString(expiry), hex.EncodeToString(mac))
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
		principal: principal,
		expiry:    expiry,
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
	tkt.parseCookieValue(c.Value)

	resource := r.Header.Get("X-Original-URI")

	if tkt.isValid() {
		allowed := ticketConfig.PrincipalIsAuthorized(tkt.principal, resource)
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
		csrfTkt.parseCookieValue(csrf)

		if authenticate(username, password) && csrfTkt.isValid() {

			tkt := createPrincipalTicket(username, time.Now().Add(time.Hour))
			c := &http.Cookie{
				Name:    "ticket",
				Value:   tkt.createCookieValue(),
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
	context.CSRF = csrf.createCookieValue()

	t.Execute(w, context)

}

var ticketConfig Config

func main() {

	ticketConfig.Read("config.json")

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/_auth", authHandler)

	log.Fatal(http.ListenAndServe(":"+fmt.Sprint(ticketConfig.Port), nil))

}
