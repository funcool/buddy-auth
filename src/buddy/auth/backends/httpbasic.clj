;; Copyright 2013-2015 Andrey Antukh <niwi@niwi.nz>
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
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [buddy.core.codecs :refer [base64->str]]
            [cuerdas.core :as str]))

(defn- parse-httpbasic-header
  "Given a request, try extract and parse
  http basic header."
  [request]
  (let [pattern (re-pattern "^Basic (.+)$")
        decoded (some->> (http/-get-header request "authorization")
                         (re-find pattern)
                         (second)
                         (base64->str))]
    (when-let [[username password] (str/split decoded #":")]
      {:username username :password password})))

(defn http-basic-backend
  "Create an instance of the http-basic based
  authentication backend.

  This backends also implements authorization
  workflow with some defaults. This means that
  you can provide own unauthorized-handler hook
  if the default not satisfies you."
  [& [{:keys [realm authfn unauthorized-handler] :or {realm "Buddy Auth"}}]]
  (when (nil? authfn)
    (throw (IllegalArgumentException. "authfn parameter is mandatory.")))
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-httpbasic-header request))
    (-authenticate [_ request data]
      (authfn request data))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request (assoc metadata :realm realm))
        (if (authenticated? request)
          (http/response "Permission denied" 403)
          (http/response "Unauthorized" 401
                         {"WWW-Authenticate" (format "Basic realm=\"%s\"" realm)}))))))
