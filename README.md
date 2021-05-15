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

### To-Do

* Improve password hashing
* Command line flags (e.g. for configuration and key generation)
* Test coverage

### **Security Considerations**

Note: this is a personal/hobby project, so I wouldn't recommend its use in
high-security environments without signficant review of your own. 

