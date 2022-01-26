;; Copyright 2013-2016 Andrey Antukh <niwi@niwi.nz>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.auth.backends.token
  "The token based authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [buddy.sign.jwt :as jwt]))

(defn- handle-unauthorized-default
  "A default response constructor for an unauthorized request."
  [request]
  (if (authenticated? request)
    {:status 403 :headers {} :body "Permission denied"}
    {:status 401 :headers {} :body "Unauthorized"}))

(defn- parse-header
  [request token-name]
  (some->> (http/-get-header request "authorization")
           (re-find (re-pattern (str "^(?i)" token-name " (.+)$")))
           (second)))

(defn jws-backend
  [{:keys [secret authfn unauthorized-handler options token-name on-error]
    :or {authfn identity token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request token-name))

    (-authenticate [_ request data]
      (try
        (authfn (jwt/unsign data secret options))
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (when (fn? on-error)
              (on-error request e))
            nil))))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))

(defn jwe-backend
  [{:keys [secret authfn unauthorized-handler options token-name on-error]
    :or {authfn identity token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request token-name))
    (-authenticate [_ request data]
      (try
        (authfn (jwt/decrypt data secret options))
        (catch clojure.lang.ExceptionInfo e
          (when (fn? on-error)
            (on-error request e))
          nil)))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))

(defn token-backend
  [{:keys [authfn unauthorized-handler token-name] :or {token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request token-name))
    (-authenticate [_ request token]
      (authfn request token))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))
