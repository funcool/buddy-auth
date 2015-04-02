;; Copyright 2013-2015 Andrey Antukh <niwi@niwi.be>
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
  (:require [buddy.auth.protocols :as proto]
            [buddy.sign.jws :as jws]
            [slingshot.slingshot :refer [try+]]
            [ring.util.response :refer [get-header response?]]))

(defn- handle-unauthorized-default [request]
  (if (:identity request)
    {:status 403 :headers {} :body "Permission denied"}
    {:status 401 :headers {} :body "Unauthorized"}))

(defn parse-authorization-header
  [request token-name]
  (some->> (get-header request "authorization")
           (re-find (re-pattern (str "^" token-name " (.+)$")))
           (second)))

(defn jws-backend
  [{:keys [secret unauthorized-handler options token-name]
    :or {token-name "Token"}}]
  (reify
    proto/IAuthentication
    (parse [_ request]
      (parse-authorization-header request token-name))
    (authenticate [_ request data]
      (try+
        (assoc request :identity (jws/unsign data secret options))
        (catch Object e
          request)))

    proto/IAuthorization
    (handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))

(defn token-backend
  [{:keys [authfn unauthorized-handler token-name] :or {token-name "Token"}}]
  {:pre [(fn? authfn)]}
  (reify
    proto/IAuthentication
    (parse [_ request]
      (parse-authorization-header request token-name))
    (authenticate [_ request token]
      (let [rsq (authfn request token)]
        (if (response? rsq) rsq
            (assoc request :identity rsq))))

    proto/IAuthorization
    (handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))
