package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() {
	ticketConfig = Config{
		Port:         8080,
		SecretKey:    []byte("YELLOW SUBMARINE"),
		ExpireLength: time.Hour,
		Principals: []Principal{
			{
				Name:      "superuser",
				Resources: []string{"ALL"},
				Hash:      "73d1b1b1bc1dabfb97f216d897b7968e44b06457920f00f2dc6c1ed3be25ad4c", // "super"
			},
			{
				Name:      "private-x",
				Resources: []string{"private/x.html"},
				Hash:      "04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb", // "user"
			},
		},
	}
}

func TestNoCookie(t *testing.T) {

	req := httptest.NewRequest("GET", "http://www.example.com", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status code %d wanted %d", resp.StatusCode, http.StatusUnauthorized)
	}

}

func TestExpiredCookie(t *testing.T) {

	tkt := createPrincipalTicket("superuser", time.Now().Add(-time.Hour))

	cookie := &http.Cookie{
		Name:    "ticket",
		Value:   tkt.EncryptAndSign(),
		Expires: time.Now().Add(time.Hour),
		Path:    "/",
	}

	req := httptest.NewRequest("GET", "http://www.example.com", nil)
	w := httptest.NewRecorder()

	req.AddCookie(cookie)

	authHandler(w, req)
	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status code %d wanted %d", resp.StatusCode, http.StatusUnauthorized)
	}

}

func TestValidCookie(t *testing.T) {

	tkt := createPrincipalTicket("superuser", time.Now().Add(time.Hour))

	cookie := &http.Cookie{
		Name:    "ticket",
		Value:   tkt.EncryptAndSign(),
		Expires: time.Now().Add(time.Hour),
		Path:    "/",
	}

	req := httptest.NewRequest("GET", "http://www.example.com/", nil)
	req.Header.Add("X-Original-URI", "/private/x.html")

	w := httptest.NewRecorder()

	req.AddCookie(cookie)

	authHandler(w, req)
	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status code %d wanted %d for user %s on resource %s", resp.StatusCode, http.StatusOK, tkt.Principal, req.Header.Get("X-Original-URI"))
	}

}
