# User Guide

## Introduction

_buddy-auth_ is a module that provides authentication and authorization
facilites for ring and ring based web applications.


### Project Maturity

Since _buddy-auth_ is in a maintenance mode and does not expect more changes.


### Install

The simplest way to use _buddy-auth_ in a clojure project is by including it in
your *_project.clj_* dependency vector:

```clojure
{buddy/buddy-auth {:mvn/version "3.0.323"}
```

This package is intended to be used with *jdk>=8*.


## Authentication

### Introduction

The buddy's approach for authentication is pretty simple and explicit.
In contrast to the vast majority of authentication libraries that I know,
_buddy_ does not mix authentication process with the authorization.

It is implemented as a pluggable backend that can be picked as is or you can
implement a new one with simple steps. This is a list of builtin backends:

| Backend name  | Namespace                      |
|---------------|--------------------------------|
| Http Basic    | `buddy.auth.backends/basic`    |
| Session       | `buddy.auth.backends/session`  |
| Token         | `buddy.auth.backends/token`    |
| Signed JWT    | `buddy.auth.backends/jws`      |
| Encrypted JWT | `buddy.auth.backends/jwe`      |

If you are not happy with the built-in backends, you can implement your own and
use it with _buddy-auth_ middleware without any problems.

The authentication process works mainly in two steps:

1. *parse*: that is responsible for analyzing the request and reading the auth
   related data (e.g. `Authorization` header, url params, etc..)
2. *auth*: with the data obtained from parse step, just try to authenticate the
   request (e.g. simple access to database for obtaining the possible user, using
   a self contained jws/jwe token, checking a key in the session, etc...)

This step does not raise any exceptions and is completely transparent to the
user. It is the responsibility of the authentication process to determine if a request
is anonymous or authenticated, nothing more.

### Backends

#### Http-Basic

The HTTP Basic authentication backend is one of the simplest and most insecure
authentication systems, but is a good first step to understanding how
_buddy-auth_ authentication works.

```clojure
(require '[ring.util.response :refer (response)])

;; Simple ring handler. This can also be a compojure router handler
;; or anything else compatible with ring middleware.

(defn my-handler
  [request]
  (if (:identity request)
    (response (format "Hello %s" (:identity request)))
    (response "Hello Anonymous")))
```

The basic step to check if a request is authenticated or not is just to check
if it comes with an `:identity` key and it contains a logical `true` (exists and
contains something different to `nil` or `false`).

This is how the authentication backend should be setup:

```clojure
(require '[buddy.auth.backends :as backends])

(defn my-authfn
  [request authdata]
  (let [username (:username authdata)
        password (:password authdata)]
    username))

(def backend (backends/basic {:realm "MyApi"
                              :authfn my-authfn}))
```

The `authfn` is responsible for the second step of authentication. It receives
the parsed auth data from request and should return a logical true value (e.g a user
id, user instance, mainly something different to `nil` and `false`). And it will
be called only if step 1 (parse) returns something.

And finally, you should wrap your ring handler with authentication and authorization
middleware:

```clojure
(require '[buddy.auth.middleware :refer [wrap-authentication
                                         wrap-authorization]])

;; Define the main handler with *app* name wrapping it
;; with authentication middleware using an instance of the
;; just created http-basic backend.

;; Define app var with handler wrapped with _buddy-auth_'s authentication
;; and authorization middleware using the previously defined backend.

(def app (-> my-handler
             (wrap-authentication backend)
             (wrap-authorization backend)))
```

From now, all requests that reach `my-handler` will be properly authenticated.


#### Session

The session backend has the simplest implementation because it relies entirely on
ring session support.

The authentication process of this backend consists of checking the `:identity`
keyword in session. If it exists and is a logical true, it is automatically
forwarded to the request under the `:identity` property.

```clojure
(require '[buddy.auth.backends :as backends])

;; Create an instance
(def backend (backends/session))

;; Wrap the ring handler.
(def app (-> my-handler
             (wrap-authentication backend)))
```


#### Token

This is a backend that uses tokens for authenticating the user. It behaves very
similarly to the basic-auth backend with the difference that instead of
authenticating with credentials it authenticates with a simple token.

Let's see an example:

```clojure
(require '[buddy.auth.backends :as backends])

;; Define a in-memory relation between tokens and users:
(def tokens {:2f904e245c1f5 :admin
             :45c1f5e3f05d0 :foouser})

;; Define an authfn, function with the responsibility
;; to authenticate the incoming token and return an
;; identity instance

(defn my-authfn
  [request token]
  (let [token (keyword token)]
    (get tokens token nil)))

;; Create an instance
(def backend (backends/token {:authfn my-authfn}))

;; Wrap the ring handler.
(def app (-> my-handler
             (wrap-authentication backend)))
```

The process of authentication of this backend consists in parsing the
"Authorization" header, extracting the token and in case the token is extracted
successfully, call the `authfn` with extracted token.

```clojure
Authorization: Token 45c1f5e3f05d0
```

The `authfn` should return something that will be associated to the `:identity`
key in the request.

The responsability of _buddy_ is just parse request and call the user function to
authenticate it. The token building and storage is a user responsability.

You can see a complete example of using this backend <<example-token,here>>.


#### Signed JWT

Is a backend that uses signed and self contained tokens to authenticate the user.

It behaves very similarly to the _Token_ backend (previously explained) with the
difference that this one does not need additional user defined logic to validate
tokens, because as we said previously, everything is self contained.

This type of token mechanism enables a completely stateless authentication because the
server does not need to store the token and related information, the token will
contain all the needed information for authentication.

Let's see a demonstrative example:

```
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer (wrap-authentication)])

(def secret "mysecret")
(def backend (backends/jws {:secret secret}))

;; and wrap your ring application with
;; the authentication middleware

(def app (-> your-ring-app
             (wrap-authentication backend)))
```

Now you should have a login endpoint in your ring application that will have the
responsibility of generating valid tokens:

```clojure
(require '[buddy.sign.jwt :as jwt])
(require '[cheshire.core :as json])

(defn login-handler
  [request]
  (let [data (:form-params request)
        user (find-user (:username data)   ;; (implementation ommited)
                        (:password data))
        token (jwt/sign {:user (:id user)} secret)]
    {:status 200
     :body (json/encode {:token token})
     :headers {:content-type "application/json"}}))
```

For more details about jwt, see the
link:https://funcool.github.io/buddy-sign/latest/#jwt[buddy-sign] documentation.

Some valuable resources for learning about stateless authentication are:

- http://lucumr.pocoo.org/2013/11/17/my-favorite-database/
- http://www.niwi.nz/2014/06/07/stateless-authentication-with-api-rest/


#### Encrypted JWT

This backend is almost identical to the previous one (signed JWT).

The main difference is that the backend uses JWE (Json Web Encryption) instead of
JWS (Json Web Signature) and it has the advantage that the content of the token is
encrypted instead of simply signed. This is useful when token may contain some
additional user information that should not be public.

It will look similar to the previous (jws) example but instead uses jwe with
asymmetric key encryption algorithm:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer (wrap-authentication)])
(require '[buddy.sign.jwe :as jwe])
(require '[buddy.core.keys :as keys])

(def pubkey (keys/public-key "pubkey.pem"))
(def privkey (keys/private-key "privkey.pem"))

(def backend
  (backends/jwe {:secret privkey
                 :options {:alg :rsa-oaep
                           :enc :a128-hs256}}))

;; and wrap your ring application with
;; the authentication middleware

(def app (-> your-ring-app
             (wrap-authentication backend)))
```

The corresponding login endpoint should have a similar aspect to this:

```clojure
(require '[buddy.sign.jwt :as jwt])
(require '[cheshire.core :as json])

(defn login-handler
  [request]
  (let [data (:form-params request)
        user (find-user (:username data)   ;; (implementation ommited)
                        (:password data))
        token (jwt/encrypt {:user (:id user)} pubkey
                           {:alg :rsa-oaep :enc :a128-hs256})]
    {:status 200
     :body (json/encode {:token token})
     :headers {:content-type "application/json"})))
```

In order to use any asymmetric encryption algorithm, you should have private/public
key pair. If you don't have one, don't worry, it is very easy to generate it using
*openssl*, see this link:https://funcool.github.io/buddy-sign/latest/#generate-keypairs[faq entry].


## Authorization

The second part of the auth process is authorization.

The authorization system is split into two parts: generic authorization and
access-rules (explained in the next section).

The generic one is based on exceptions, and consists in raising an unauthorized
exception in case the request is considered unauthorized. The access rules
system is based on some kind of rules attached to the handler or an _URI_ and
that rules determine if a request is authorized or not.


### Exception-Based

This authorization approach is based on wrapping everything in a try/catch block
which only handles specific exceptions. When an unauthorized exception is caught,
it executes a specific function to handle it or reraises the exception.

With this approach, you can define your own middlewares/decorators using custom
authorization logic with fast skip, raising an unauthorized exception using the
`throw-unauthorized` function.

```clojure
(require '[buddy.auth :refer [authenticated? throw-unauthorized]])
(require '[ring.util.response :refer (response redirect)])

(defn home-controller
  [request]
  (when (not (authenticated? request))
    (throw-unauthorized {:message "Not authorized"}))
  (response "Hello World"))
```

Just like the authentication system, authorization is also implemented using
plugable backends.

All built-in backends already implement the authorization protocol with default
behavior. The default behavior can be overridden passing the `:unauthorized-handler`
option to the backend constructor:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])

;; Simple self defined handler for unauthorized requests.
(defn my-unauthorized-handler
  [request metadata]
  (-> (response "Unauthorized request")
      (assoc :status 403)))

(def backend (backends/basic
              {:realm "API"
               :authfn my-auth-fn
               :unauthorized-handler my-unauthorized-handler}))

(def app (-> your-handler
             (wrap-authentication backend)
             (wrap-authorization backend)))
```


### Access Rules

The access rules system is another part of authorization. It consists of matching
an url to specific access rules logic.

The access rules consist of an ordered list that contains mappings between urls
and rule handlers using link:https://github.com/weavejester/clout[clout] url
matching syntax or regular expressions.

```clojure
[{:uri "/foo"
  :handler user-access}
```

```clojure
[{:uris ["/foo" "/bar"]
  :handler user-access}
```

```clojure
[{:pattern #"^/foo$"
  :handler user-access}
```

An access rule can also match against certain HTTP methods, by using the
*:request-method* option. *:request-method* can be a keyword or a set of keywords.

An example of an access rule that matches only GET requests:

```clojure
[{:uri "/foo"
  :handler user-access
  :request-method :get}
```


#### Rules Handlers

The rule handler is a plain function that accepts a request as a parameter and
should return `accessrules/success` or `accessrules/error`.

The `success` is a simple mark that means that handlers pass the validation and
`error` is a mark that means the opposite, that the handler does not pass the
validation. Instead of returning plain boolean values, this approach allows handlers
to return errors messages or even a ring response.

This is a simple example of the aspect of one rule handler:

```clojure
(require '[buddy.auth.accessrules :refer (success error)])

(defn authenticated-user
  [request]
  (if (:identity request)
    true
    (error "Only authenticated users allowed")))
```

These values are considered success marks: *true* and *success* instances. These are
considered error  marks: *nil*, *false*, and *error* instances. Error instances may
contain a string as an error message or a ring response hash-map.

Also, a rule handler can be a composition of several rule handlers using logical
operators.

```clojure
{:and [authenticated-user other-handler]}
{:or [authenticated-user other-handler]}

;; Logical expressions can be nested as deep as you wish
;; with hypotetical rule handlers with self descriptive name.
{:or [should-be-admin
      {:and [should-be-safe
             should-be-authenticated]}]}}
```

This is an example of how a composed rule handler can be used in an
access rules list:

```clojure
[{:pattern #"^/foo$"
  :handler {:and [authenticated-user admin-user]}}]
```

Additionally, if you are using *clout* based syntax for matching access rules, the
request in a rule handler will contain `:match-params` with clout matched uri params.


#### Usage

Now, knowing how access rules and rule handlers can be defined, it is time to see
how we can use it in our ring applications.

_buddy-auth_ exposes two ways to do it:

* Using a _wrap-access-rules_ middleware.
* Using a _restrict_ decorator for assigning specific rules handlers to concrete
  ring handler.

Here are couple of examples of how we could do it:

```clojure
;; Rules handlers used on this example are ommited for code clarity
;; Each handler represents authorization logic indicated by its name.

(def rules [{:pattern #"^/admin/.*"
             :handler {:or [admin-access operator-access]}}
            {:pattern #"^/login$"
             :handler any-access}
            {:pattern #"^/.*"
             :handler authenticated-access}])

;; Define default behavior for not authorized requests
;;
;; This function works like a default ring compatible handler
;; and should implement the default behavior for requests
;; which are not authorized by any defined rule

(defn on-error
  [request value]
  {:status 403
   :headers {}
   :body "Not authorized"})

;; Wrap the handler with access rules (and run with jetty as example)
(defn -main
  [& args]
  (let [options {:rules rules :on-error on-error}
        app     (wrap-access-rules your-app-handler options)]
    (run-jetty app {:port 3000})))
```

If a request uri does not match any regular expression then the default policy is
used. The default policy in _buddy-auth_ is *allow* but you can change the default
behavior specifying a `:reject` value in the `:policy` option.

Additionally, instead of specifying the global _on-error_ handler, you can set a
specific behavior on a specific access rule, or use the _:redirect_ option to
simply redirect a user to specific url.

```clojure
(def rules [{:pattern #"^/admin/.*"
             :handler {:or [admin-access operator-access]}
             :redirect "/notauthorized"}
            {:pattern #"^/login$"
             :handler any-access}
            {:pattern #"^/.*"
             :handler authenticated-access
             :on-error (fn [req _] (response "Not authorized ;)"))}])
```

The access rule options always takes precedence over the global ones.

Then, if you don't want an external rules list and simply want to apply some rules
to specific ring views/handlers, you can use the `restrict` decorator. Let's see it
in action:

```clojure
(require '[buddy.auth.accessrules :refer [restrict]])

(defn home-controller
  [request]
  {:body "Hello World" :status 200})

(defroutes app
  (GET "/" [] (restrict home-controller {:handler should-be-authenticated
                                         :on-error on-error}))
```


## Examples

### Http Basic Auth Example

This example tries to show the way to setup http basic auth in a simple ring based
application.

Just run the following commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +httpbasic-example run
```

And redirect your browser to http://localhost:3000/.

The credentials are: `admin` / `secret` and `test` / `secret`.

You can see the example code here:
https://github.com/funcool/buddy-auth/tree/master/examples/httpbasic


### Session Auth Example

This example tries to show the way to setup session based auth in a simple ring
based application.

Just run the following commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +session-example run
```

And redirect your browser to http://localhost:3000/.

The credentials are: `admin` / `secret` and `test` / `secret`.

You can see the example code here:
https://github.com/funcool/buddy-auth/tree/master/examples/session


### Token Auth Example

This example tries to show the way to setup token based auth in a simple ring based
application.

Just run the following commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +token-example run
```

You can use *curl* for play with the authentication example:

```
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:3000/login
* Connected to localhost (::1) port 3000 (#0)
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
>
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:54:02 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 44
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"token":"fe562338bf1604bd175722e32a4d7115"}
```

```
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token fe562338bf1604bd175722e32a4d7115" http://localhost:3000/
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Authorization: Token fe562338bf1604bd175722e32a4d7115
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:54:40 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 55
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user:admin"}
```

You can see the example code here:
https://github.com/funcool/buddy-auth/tree/master/examples/token


### JWE Token Auth Example

This example tries to show the way to setup jwe stateless token based auth in a
simple ring based application.

Just run the following commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +jwe-example run
```

You can use *curl* for play with the authentication example:

```
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:3000/login
* Connected to localhost (::1) port 3000 (#0)
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
>
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:52:11 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 189
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"token":"eyJhbGciOiJBMjU2S1ciLCJ0eXAiOiJKV1MiLCJlbmMiOiJBMTI4R0NNIn0.Q672y_lD3bOU_qm5U0RDKS-YszRHfkFu.vDZaAJPz8uL5q1A4.LonJtHZMA_Ty53YBmr1zpE7-SIbTJgVgme--Tjj25dHN.goYEyM3JZgYlbARo8CDk0g"}
```

Perform an authenticated request (using previously obtained token):

```
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token eyJhbGciOiJBMjU2S1ciLCJ0eXAiOiJKV1MiLCJlbmMiOiJBMTI4R0NNIn0.Q672y_lD3bOU_qm5U0RDKS-YszRHfkFu.vDZaAJPz8uL5q1A4.LonJtHZMA_Ty53YBmr1zpE7-SIbTJgVgme--Tjj25dHN.goYEyM3JZgYlbARo8CDk0g" http://localhost:3000/
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Authorization: Token eyJhbGciOiJBMjU2S1ciLCJ0eXAiOiJKV1MiLCJlbmMiOiJBMTI4R0NNIn0.Q672y_lD3bOU_qm5U0RDKS-YszRHfkFu.vDZaAJPz8uL5q1A4.LonJtHZMA_Ty53YBmr1zpE7-SIbTJgVgme--Tjj25dHN.goYEyM3JZgYlbARo8CDk0g
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:52:59 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 84
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user {:user \"admin\", :exp 1451919131}"}
```

You can see the example code here:
https://github.com/funcool/buddy-auth/tree/master/examples/jwe


### Signed JWT Auth Example

This example tries to show the way to setup jws stateless token based auth in a
simple ring based application.

Just run the following commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +jws-example run
```

You can use *curl* for play with the authentication example:

```
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:3000/login
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
>
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:49:30 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 180
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0NTE5MTg5NzB9.Kvpr1jW7JBCZYUlFjAf7xnqMZSTpSVggAgiZ6_RGZuTi1wUuP_-E8MJff23GuCwpT9bbbHNTk84uV2cdg7rKTw"}
```

Perform an authenticated request (using previously obtained token):

```
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0NTE5MTg5NzB9.Kvpr1jW7JBCZYUlFjAf7xnqMZSTpSVggAgiZ6_RGZuTi1wUuP_-E8MJff23GuCwpT9bbbHNTk84uV2cdg7rKTw" http://localhost:3000/
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Authorization: Token eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0NTE5MTg5NzB9.Kvpr1jW7JBCZYUlFjAf7xnqMZSTpSVggAgiZ6_RGZuTi1wUuP_-E8MJff23GuCwpT9bbbHNTk84uV2cdg7rKTw
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:50:15 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 84
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user {:user \"admin\", :exp 1451918970}"}
```

You can see the example code here:
https://github.com/funcool/buddy-auth/tree/master/examples/jws


## FAQ

*What is the difference with Friend?*

_buddy-auth_ authorization/authentication facilities are more low level and less
opinionated than friend, and allow you to easily build other high level abstractions
over them. Technically, friend abstraction can be built on top of _buddy-auth_.


*How can I use _buddy_ with link:http://clojure-liberator.github.io/liberator/[liberator]?*

By design, _buddy_ has authorization and authentication well
separated. This helps a lot if you want use only one part of it (ex:
authentication only) without including the other.

In summary: yes, you can use _buddy-auth_ with liberator.


*Can I use _buddy-auth_ with pedestal?*

Although is not mentioned in this documentation, you can use _buddy-auth_ with
pedestal without any problems.

https://juxt.pro/blog/posts/securing-your-clojurescript-app.html


*Can I use _buddy-auth_ with catacumba?*

Not directly.

The design of _buddy-auth_ api is intrinsically blocking just because ring and ring
based abstractions are also blocking. However _catacumba_ is asyncronous toolkit and
it comes with its own, builtint variant of _buddy-auth_ designed for asynchronous
workflow (reusing the underlying _buddy-sign_, _buddy-core_ and _buddy-hashers_
modules).


## Developers Guide

### Contributing

Unlike Clojure and other Clojure contributed libraries _buddy-auth_ does not have many
restrictions for contributions. Just open an issue or pull request.


### Philosophy

Five most important rules:

- Beautiful is better than ugly.
- Explicit is better than implicit.
- Simple is better than complex.
- Complex is better than complicated.
- Readability counts.

All contributions to _buddy-auth_ should keep these important rules in mind.


### Get the Code

_buddy-auth_ is open source and can be found on link:https://github.com/funcool/buddy-auth[github].

You can clone the public repository with this command:

```
git clone https://github.com/funcool/buddy-auth
```


### Run tests

For running tests just execute this:

```bash
lein test
```


### License

_buddy-auth_ is licensed under Apache 2.0 License. You can see the complete text
of the license on the root of the repository on `LICENSE` file.
