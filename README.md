# go-http-auth-request

This project provides a simple Go HTTP server that can interface with nginx's
http_auth_request_module. It does so by implementing a ticketing system that
understands principals (users) and resources (URLs). It can be used quite simply
to provide a basic authentication layer to nginx-hosted websites.

This is a practical "learn go" type project, more than a production-ready tool
(see *Security Considerations*, below).

## Design Approach

Authentication is JWT-like, in that cookies store the signed ticket. There's JSON
parsing logic built into `config`, which handles server configuration and
implements a basic roster of principals and permissions.

Cookies are encrypt-then-MAC'd values of a given principal and expiry ticket. The
server itself presents a basic login page and handles sub-requests to a specified
`_auth` URI. Returns 200 if the user has a valid ticket or kicks back 401 for
nginx to handle if the user is not ticketed or unauthorized for that resource.

Does require some `nginx` trickery to get working, see *Setup*, below.

## Setup

To do.

### To-Do

* Improve password hashing
* Command line flags (e.g. for configuration and key generation)
* Test coverage

### **Security Considerations**

Note: this is a personal/hobby project, so I wouldn't recommend its use in
high-security environments without signficant review of your own. 

