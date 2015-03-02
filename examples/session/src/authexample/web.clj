;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; a full buddy auth example
;
; "/login" shows a login form
; after successful login the page redirects to a home page 
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ns authexample.web
  (:require [compojure.route :as route]
            [compojure.core :refer :all]
            [compojure.response :refer [render]]
            [clojure.java.io :as io]
            [ring.util.response :refer [response redirect content-type]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.adapter.jetty :as jetty]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])
  (:gen-class))


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
    (response (slurp (io/resource "index.html")))))


;; Global var that stores valid users with their
;; respective passwords.

(def authdata {:admin "secret"
               :test "secret"})

;; Login page controller
;; It returns a login page on get requests.

(defn login
  [request]
  (render (slurp (io/resource "login.html")) request))

;; Authenticate Handler
;; Respons to post requests in same url as login and is responsible to
;; identify the incoming credentials and set the appropiate authenticated
;; user into session. `authdata` will be used as source of valid users.

(defn login-authenticate
  [request]
  (let [username (get-in request [:form-params "username"])
        password (get-in request [:form-params "password"])
        session (:session request)]
    (if-let [found-password (get authdata (keyword username))]
      (if (= found-password password)
        (let [nexturl (get-in request [:query-params :next] "/")
              session (assoc session :identity (keyword username))]
          (-> (redirect nexturl)
              (assoc :session session)))
        (render (slurp (io/resource "login.html")) request))
      (render (slurp (io/resource "login.html")) request))))


;; Logout handler
;; It is responsible of cleaing session.

(defn logout
  [request]
  (-> (redirect "/login")
      (assoc :session {})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes and Middlewares                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; User defined application routes using compojure routing library.
;; Note: no any middleware for authorization, all authorization system
;; is totally decoupled from main routes.

(defroutes app
  (GET "/" [] home)
  (GET "/login" [] login)
  (POST "/login" [] login-authenticate)
  (GET "/logout" [] logout))


;; Self defined unauthorized handler
;; This function is responsible of handling unauthorized requests.
;; (When unauthorized exception is raised by some handler)

(defn unauthorized-handler
  [request metadata]
  (cond
    ;; If request is authenticated, raise 403 instead
    ;; of 401 (because user is authenticated but permission
    ;; denied is raised).
    (authenticated? request)
    (-> (render (slurp (io/resource "error.html")) request)
        (assoc :status 403))

    ;; In other cases, redirect it user to login.
    :else
    (let [current-url (:uri request)]
      (redirect (format "/login?next=%s" current-url)))))


;; Create an instance of auth backend.

(def auth-backend
  (session-backend {:unauthorized-handler unauthorized-handler}))

; the Ring app definition including the authentication backend
(def app (-> app
            (wrap-authorization auth-backend)
            (wrap-authentication auth-backend)
            (wrap-params)
            (wrap-session)))
