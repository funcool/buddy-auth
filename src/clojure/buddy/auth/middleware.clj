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

(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.accessrules :as accessrules]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [ring.util.response :refer [response response?]]
            [slingshot.slingshot :refer [throw+ try+]])
  (:import buddy.exceptions.UnauthorizedAccessException))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn wrap-authentication
  "Ring middleware that enables authentication
  for your ring handler."
  [handler backend]
  (fn [request]
    (let [request (assoc request :auth-backend backend)
          rsq     (proto/parse backend request)]
      (if (response? rsq) rsq
        (if (nil? rsq)
          (handler request)
          (let [rsq (proto/authenticate backend request rsq)]
            (if (response? rsq) rsq
              (handler (or rsq request)))))))))

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
    proto/IAuthentication
    (handle-unauthorized [_ request errordata]
      (callable request errordata))))

(defn wrap-authorization
  "Ring middleware that enables authorization
  workflow for your ring handler.

  The `backend` parameter should be a plain function
  that accepts two paramerts: request and errordata
  hashmap, or an instance that satisfies IAuthorization
  protocol."
  [handler backend]
  (let [backend (cond
                  (fn? backend)
                  (fn->authorization-backend backend)

                  (satisfies? proto/IAuthentication backend)
                  backend)]
    (fn [request]
      (try+
       (handler request)
       (catch Object e
         (if (satisfies? proto/IAuthorizationdError e)
           (let [errordata (proto/get-error-data e)]
             (proto/handle-unauthorized backend request errordata))
           (throw+)))))))

(extend-protocol proto/IAuthorizationdError
  buddy.exceptions.UnauthorizedAccessException
  (get-error-data [this]
    (.-metadata this)))
