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
;; If incoming user is not authenticated it raises a
;; not authenticated exception, else it simply shows a
;; hello world message.

(defn home
  [request]
  (if-not (authenticated? request)
    (throw-unauthorized)
    (let [content (slurp (io/resource "index.html"))]
      (response content))))

;; Login page controller
;; It returns a login page on get requests.

(defn login
  [request]
  (let [content (slurp (io/resource "login.html"))]
    (render content request)))

;; Logout handler
;; Responsible for clearing the session.

(defn logout
  [request]
  (-> (redirect "/login")
      (assoc :session {})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication                                   ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def authdata
  "Global var that stores valid users with their
   respective passwords."
  {:admin "secret"
   :test "secret"})

;; Authentication Handler
;; Used to respond to POST requests to /login.

(defn login-authenticate
  "Check request username and password against authdata
  username and passwords.

  On successful authentication, set appropriate user
  into the session and redirect to the value of
  (:next (:query-params request)). On failed
  authentication, renders the login page."
  [request]
  (let [username (get-in request [:form-params "username"])
        password (get-in request [:form-params "password"])
        session (:session request)
        found-password (get authdata (keyword username))]
    (if (and found-password (= found-password password))
      (let [next-url (get-in request [:query-params :next] "/")
            updated-session (assoc session :identity (keyword username))]
        (-> (redirect next-url)
            (assoc :session updated-session)))
      (let [content (slurp (io/resource "login.html"))]
        (render content request)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes and Middlewares                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; User defined application routes using compojure
;; routing library.
;;
;; Note: We do not use middleware for authorization,
;; all of the authorization system is decoupled from
;; main routes.

(defroutes app
  (GET "/" [] home)
  (GET "/login" [] login)
  (POST "/login" [] login-authenticate)
  (GET "/logout" [] logout))

;; User defined unauthorized handler
;;
;; This function is responsible for handling
;; unauthorized requests (when unauthorized exception
;; is raised by some handler)

(defn unauthorized-handler
  [request metadata]
  (cond
    ;; If request is authenticated, raise 403 instead
    ;; of 401 (because user is authenticated but permission
    ;; denied is raised).
    (authenticated? request)
    (-> (render (slurp (io/resource "error.html")) request)
        (assoc :status 403))
    ;; In other cases, redirect the user to login page.
    :else
    (let [current-url (:uri request)]
      (redirect (format "/login?next=%s" current-url)))))

;; Create an instance of auth backend.

(def auth-backend
  (session-backend {:unauthorized-handler unauthorized-handler}))

(defn -main
  [& args]
  (as-> app $
    (wrap-authorization $ auth-backend)
    (wrap-authentication $ auth-backend)
    (wrap-params $)
    (wrap-session $)
    (jetty/run-jetty $ {:port 3000})))
