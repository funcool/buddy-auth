(ns authexample.web
  (:require [compojure.route :as route]
            [compojure.core :refer :all]
            [compojure.response :refer [render]]
            [clojure.java.io :as io]
            [ring.util.response :refer [response redirect content-type]]
            [ring.adapter.jetty :as jetty]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends.httpbasic :refer [http-basic-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])
  (:gen-class))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Controllers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Home page controller (ring handler)
;; If incoming user is not authenticated it raises a not authenticated
;; exception, else simple shows a hello world message.

(defn home
  [req]
  (if-not (authenticated? req)
    (throw-unauthorized)
    (response (slurp (io/resource "index.html")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes and Middlewares
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; User defined application routes using compojure routing library.
;; Note: no any middleware for authorization, all authorization system
;; is totally decoupled from main routes.

(defroutes app
  (GET "/" [] home))

;; Global var that stores valid users with their
;; respective passwords.
(def authdata {:admin "secret"
               :test "secret"})

;; Define function that is responsible of authenticating requests.
;; In this case it receives a map with username and password and i
;; should return a value that can be considered a "user" instance
;; and should be a logical true.

(defn my-authfn
  [req {:keys [username password]}]
  (when-let [user-password (get authdata (keyword username))]
    (when (= password user-password)
      (keyword username))))

;; Create an instance of auth backend without explicit handler for
;; unauthorized request. (That leaves the responsability to default
;; backend implementation.

(def auth-backend
  (http-basic-backend {:realm "MyExampleSite"
                       :authfn my-authfn}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Main Entry Point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def app (-> app
             (wrap-authorization auth-backend)
             (wrap-authentication auth-backend)))
