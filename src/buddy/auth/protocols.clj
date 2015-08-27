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

(ns buddy.auth.protocols
  "Main authentication and authorization abstractions
  defined as protocols.")

(defprotocol IAuthentication
  "Protocol that defines unfied workflow steps for
  all authentication backends."
  (parse [_ request]
    "Parse token from the request. If it returns `nil`
    the `authenticate` phase will be skipped and the
    handler will called directly.")
  (authenticate [_ request data]
    "Given a request and parsed data (from previous step)
    and try authenticate this data and return a new request
    object with `:identity` key attached.

    This method is only called if `parse` function,
    previouslly are returned not nil data.

    Some backends can be extended with user defined function
    for as ex, lookup user information in a database, etc..."))

(defprotocol IAuthorization
  "Protocol that defines unfied workflow steps for
  authorization exceptions."
  (handle-unauthorized [_ request metadata]
    "This function is executed when a `NotAuthorizedException`
    exception is intercepted by authorization wrapper.

    It should return a valid ring response."))

(defprotocol IAuthorizationdError
  "Abstraction that allows to user extend the exception
  based authorization system with own types."
  (get-error-data [_] "Ger error information."))
