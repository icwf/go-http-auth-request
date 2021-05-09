# go-http-auth-request

This project provides a simple Go HTTP server that can interface with nginx's
http_auth_request_module. It does so by implementing a ticketing system that
understands principals (users) and resources (URLs). It can be used quite simply
to provide a basic authentication layer to nginx-hosted websites.

Note: this is a personal/hobby project, so I wouldn't recommend its use in
high-security environments without signficant review of your own.

