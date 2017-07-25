;; Copyright 2013-2017 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.accessrules :as accessrules]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated? throw-unauthorized]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn authenticate-request
  "A function that runs the authentication backend chain for
  the provided request and return the identity of the first
  matched backend (backend that properly authenticates the
  provided request).

  NOTE: this function is for internal use, it is public
  because it is helpful in environments different to ring."
  [request backends]
  (loop [[backend & backends] backends]
    (when backend
      (let [request (assoc request :auth-backend backend)]
        (or (some->> request
                     (proto/-parse backend)
                     (proto/-authenticate backend request))
            (recur backends))))))

(defn authentication-request
  "Updates request with authentication. If multiple `backends` are
  given each of them gets a chance to authenticate the request.

  NOTE: this function is for internal use, it is public
  because it is helpful in environments different to ring."
  [request & backends]
  (if-let [authdata (authenticate-request request backends)]
    (assoc request :identity authdata)
    request))

(defn wrap-authentication
  "Ring middleware that enables authentication for your ring
  handler. When multiple `backends` are given each of them gets a
  chance to authenticate the request."
  [handler & backends]
  (fn [request]
    (handler (apply authentication-request request backends))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authorization
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- fn->authorization-backend
  "Given a function that receives two parameters
  return an anonymous object that implements
  IAuthorization protocol."
  [callable]
  {:pre [(fn? callable)]}
  (reify
    proto/IAuthorization
    (-handle-unauthorized [_ request errordata]
      (callable request errordata))))

(defn authorization-error
  "Handles authorization errors.

  The `backend` parameter should be a plain function
  that accepts two parameters: request and errordata hashmap,
  or an instance that satisfies IAuthorization protocol."
  [request e backend]
  (let [backend (cond
                  (fn? backend)
                  (fn->authorization-backend backend)

                  (satisfies? proto/IAuthorization backend)
                  backend)]
    (if (instance? clojure.lang.ExceptionInfo e)
      (let [data (ex-data e)]
        (if (= (:buddy.auth/type data) :buddy.auth/unauthorized)
          (->> (:buddy.auth/payload data)
               (proto/-handle-unauthorized backend request))
          (throw e)))
      (if (satisfies? proto/IAuthorizationdError e)
        (->> (proto/-get-error-data e)
             (proto/-handle-unauthorized backend request))
        (throw e)))))

(defn wrap-authorization
  "Ring middleware that enables authorization
  workflow for your ring handler.

  The `backend` parameter should be a plain function
  that accepts two parameters: request and errordata
  hashmap, or an instance that satisfies IAuthorization
  protocol."
  [handler backend]
  (fn [request]
    (try (handler request)
         (catch Exception e
           (authorization-error request e backend)))))
