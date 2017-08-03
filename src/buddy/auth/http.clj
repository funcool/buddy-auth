;; Copyright 2015-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.auth.http
  "The http request response abstraction for
  builtin auth/authz backends.")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocols Definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IRequest
  (-get-header [req name] "Get a value of header."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn response
  "A multi arity function that creates
  a ring compatible response."
  ([body]
   {:status 200 :body body :headers {}})
  ([body status]
   {:status status :body body :headers {}})
  ([body status headers]
   {:status status :body body :headers headers}))

(defn response?
  [resp]
  (and (map? resp)
       (integer? (:status resp))
       (map? (:headers resp))))

(defn redirect
  "Returns a Ring compatible response for an HTTP 302 redirect."
  ([url] (redirect url 302))
  ([url status]
   {:status  status :body "" :headers {"Location" url}}))

(defn find-header
  "Looks up a header in a headers map case insensitively,
  returning the header map entry, or nil if not present."
  [headers ^String header-name]
  (first (filter #(.equalsIgnoreCase header-name (name (key %))) headers)))

(extend-protocol IRequest
  clojure.lang.IPersistentMap
  (-get-header [request header-name]
    (some-> (:headers request) (find-header header-name) val)))
