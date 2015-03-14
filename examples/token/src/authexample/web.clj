(ns authexample.web
  (:require [compojure.route :as route]
            [compojure.core :refer :all]
            [compojure.response :refer [render]]
            [clojure.java.io :as io]
            [ring.util.response :refer [response redirect content-type]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.json :refer [wrap-json-response wrap-json-body]]
            [ring.adapter.jetty :as jetty]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends.token :refer [token-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])
  (:gen-class))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Semantic response helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn ok [d] {:status 200 :body d})
(defn bad-request [d] {:status 400 :body d})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Token generator helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn random-token
  []
  (let [randomdata (nonce/random-bytes 16)]
    (codecs/bytes->hex randomdata)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Controllers                                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Home page controller (ring handler)
;; If incoming user is not authenticated it raises a not authenticated
;; exception, else simple shows a hello world message.

(defn home
  [request]
  (if-not (authenticated? request)
    (throw-unauthorized)
    (ok {:status "Logged" :message (str "hello logged user"
                                        (:identity request))})))


;; Global var that stores valid users with their
;; respective passwords.

(def authdata {:admin "secret"
               :test "secret"})

;; Global storage for store generated tokens.
(def tokens (atom {}))

;; Authenticate Handler
;; Respons to post requests in same url as login and is responsible to
;; identify the incoming credentials and set the appropiate authenticated
;; user into session. `authdata` will be used as source of valid users.

(defn login
  [request]
  (let [username (get-in request [:body :username])
        password (get-in request [:body :password])
        valid? (some-> authdata
                       (get (keyword username))
                       (= password))]
    (if valid?
      (let [token (random-token)]
        (swap! tokens assoc (keyword token) (keyword username))
        (ok {:token token}))
      (bad-request {:message "wrong auth data"}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes and Middlewares                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; User defined application routes using compojure routing library.
;; Note: no any middleware for authorization, all authorization system
;; is totally decoupled from main routes.

(defroutes app
  (GET "/" [] home)
  (POST "/login" [] login))

(defn my-authfn
  [req token]
  (when-let [user (get @tokens (keyword token))]
    user))

;; Create an instance of auth backend.

(def auth-backend
  (token-backend {:authfn my-authfn}))

; the Ring app definition including the authentication backend
(def app (-> app
            (wrap-authorization auth-backend)
            (wrap-authentication auth-backend)
            (wrap-json-response {:pretty false})
            (wrap-json-body {:keywords? true :bigdecimals? true})))
