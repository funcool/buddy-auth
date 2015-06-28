# buddy-auth example using token

This example application shows how to use buddy auth with token based authentication.

Users:
* user: admin, password "secret"
* user: test, password "secret"


## Running the app ##

```lein ring server-headless```

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
< Date: Sat, 14 Mar 2015 18:32:15 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 44
< Server: Jetty(7.6.13.v20130916)
<
* Connection #0 to host localhost left intact
{"token":"61a746a1bbfee2116727db66ddfcb781"}
```

### Make authenticated request ###

```text
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token 61a746a1bbfee2116727db66ddfcb781" http://localhost:9090/
* Connected to localhost (::1) port 9090 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.40.0
> Host: localhost:9090
> Accept: */*
> Content-Type: application/json
> Authorization: Token 61a746a1bbfee2116727db66ddfcb781
>
< HTTP/1.1 200 OK
< Date: Sat, 14 Mar 2015 18:35:56 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 55
< Server: Jetty(7.6.13.v20130916)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user:admin"}
```
