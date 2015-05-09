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

(ns buddy.auth.protocols
  "Main authentication and authorization abstractions
  defined as protocols.")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocols Definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IAuthentication
  "Protocol that defines unfied workflow steps for
  all authentication backends."
  (parse [_ request]
    "Parse token (from cookie, session or any other
    http header) and return it.

    If this function returns a valid ring response,
    your handler are never called and response is returned
    inmediatelly.")
  (authenticate [_ request data]
    "Given a request and parsed data (from previous step)
    and try authenticate this data and return a new request
    object with `:identity` key attached.

    This method is only called if `parse` function,
    previouslly are returned not nil and not response data.

    Some backends can be extended with user defined function
    for as ex, lookup user information in a database, etc..."))

(defprotocol IAuthorization
  "Protocol that defines unfied workflow steps for
  authorization exceptions."
  (handle-unauthorized [_ request metadata]
    "This function is executed when a `NotAuthorizedException`
    exception is intercepted by authorization wrapper.

    It should return a valid ring response."))

(defprotocol IRequest
  (get-header [req name] "Get a value of header."))

(defprotocol IResponse
  (response? [resp] "Check if `resp` is a response."))

(defprotocol IAuthorizationdError
  "Abstraction that allows to user extend the exception
  based authorization system with own types."
  (get-error-data [_] "Ger error information."))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocols builtin implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn find-header
  "Looks up a header in a headers map case insensitively,
  returning the header map entry, or nil if not present."
  [headers ^String header-name]
  (first (filter #(.equalsIgnoreCase header-name (key %)) headers)))

(extend-protocol IRequest
  clojure.lang.IPersistentMap
  (get-header [request header-name]
    (some-> (:headers request) (find-header header-name) val)))

(extend-protocol IResponse
  nil
  (response? [_]
    false)

  Object
  (response? [_] false)

  clojure.lang.IPersistentMap
  (response? [response]
    (and (integer? (:status response))
         (map? (:headers response)))))
