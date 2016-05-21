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

(ns buddy.auth.backends.httpbasic
  "The http-basic authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [cuerdas.core :as str]))

(defn- parse-header
  "Given a request, try to extract and parse
  the http basic header."
  [request]
  (let [pattern (re-pattern "^Basic (.+)$")
        decoded (some->> (http/-get-header request "authorization")
                         (re-find pattern)
                         (second)
                         (b64/decode)
                         (codecs/bytes->str))]
    (when-let [[username password] (str/split decoded #":" 2)]
      {:username username
       :password password})))

(defn http-basic-backend
  [& [{:keys [realm authfn unauthorized-handler] :or {realm "Buddy Auth"}}]]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request))
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
