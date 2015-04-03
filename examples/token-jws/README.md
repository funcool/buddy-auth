# buddy-auth example using JWS

This example application shows how to use buddy auth with JWS based authentication.

Users:
* user: admin, password "secret"
* user: test, password "secret"


## Running the app ##

``` lein ring server-headless```

The app will by default start on port 9090

## Example api requests ##

### Login ###

```text
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:9090/login
* Connected to localhost (::1) port 9090 (#0)
> POST /login HTTP/1.1
> User-Agent: curl/7.40.0
> Host: localhost:9090
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
> 
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Sat, 14 Mar 2015 18:43:19 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 115
< Server: Jetty(7.6.13.v20130916)
< 
* Connection #0 to host localhost left intact
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4ifQ.zUygXWduOwO7fZUf6fjPz02oV1OeUFkgqaT3J3g1yng"}
```

### Make authenticated request ###

```text
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4ifQ.zUygXWduOwO7fZUf6fjPz02oV1OeUFkgqaT3J3g1yn" http://localhost:9090/
* Connected to localhost (::1) port 9090 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.40.0
> Host: localhost:9090
> Accept: */*
> Content-Type: application/json
> Authorization: Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4ifQ.zUygXWduOwO7fZUf6fjPz02oV1OeUFkgqaT3J3g1yng
> 
< HTTP/1.1 200 OK
< Date: Sat, 14 Mar 2015 18:48:28 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 67
< Server: Jetty(7.6.13.v20130916)
< 
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user {:user \"admin\"}"}
```
