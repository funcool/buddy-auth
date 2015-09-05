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

(ns buddy.auth.backends.session
  "The session based authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [clojure.string :refer [split]]))

(defn session-backend
  "Create an instance of the http session based
  authentication backend.

  This backends also implements authorization
  workflow with some defaults. This means that
  you can provide own unauthorized-handler hook
  if the default not satisfies you."
  [& [{:keys [unauthorized-handler]}]]
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (:identity (:session request)))
    (-authenticate [_ request data]
      data)

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (if (authenticated? request)
          (http/response "Permission denied" 403)
          (http/response "Unauthorized" 401))))))
