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

(ns buddy.auth.backends.httpbasic
  "The http-basic authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth :refer [authenticated?]]
            [buddy.core.codecs :refer [base64->str]]
            [cuerdas.core :as str]
            [ring.util.response :refer [response header status]]))

(defn- parse-httpbasic-header
  "Given a request, try extract and parse
  http basic header."
  [request]
  (let [pattern (re-pattern "^Basic (.+)$")
        decoded (some->> (proto/get-header request "authorization")
                         (re-find pattern)
                         (second)
                         (base64->str))]
    (when-let [[username password] (str/split decoded #":")]
      {:username username :password password})))

(defn http-basic-backend
  "Given some options, create a new instance
  of HttpBasicBackend and return it."
  [& [{:keys [realm authfn unauthorized-handler] :or {realm "Buddy Auth"}}]]
  (when (nil? authfn)
    (throw (IllegalArgumentException. "authfn parameter is mandatory.")))
  (reify
    proto/IAuthentication
    (parse [_ request]
      (parse-httpbasic-header request))
    (authenticate [_ request data]
      (let [rsq (authfn request data)]
        (if (proto/response? rsq) rsq
            (assoc request :identity rsq))))

    proto/IAuthorization
    (handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request (assoc metadata :realm realm))
        (if (authenticated? request)
          (-> (response "Permission denied")
              (status 403))
          (-> (response "Unauthorized")
              (header "WWW-Authenticate" (format "Basic realm=\"%s\"" realm))
              (status 401)))))))
