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

(ns buddy.auth.backends
  (:require [buddy.auth.backends.httpbasic :as httpbasic]
            [buddy.auth.backends.token :as token]
            [buddy.auth.backends.session :as session]))

(defn basic
  "Create an instance of the http-basic based
  authentication backend.

  This backend also implements authorization
  workflow with some defaults. This means that
  you can provide your own unauthorized-handler hook
  if the default one does not satisfy you."
  ([] (basic nil))
  ([opts] (httpbasic/http-basic-backend opts)))

(def http-basic
  "Alias for `basic`."
  basic)

(defn session
  "Create an instance of the http session based
  authentication backend.

  This backend also implements authorization
  workflow with some defaults. This means that
  you can provide your own unauthorized-handler hook
  if the default one does not satisfy you."
  ([] (session nil))
  ([opts] (session/session-backend opts)))

(defn jws
  "Create an instance of the jws (json web signature)
  based authentication backend.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([] (jws nil))
  ([opts] (token/jws-backend opts)))

(defn jwe
  "Create an instance of the jwe (json web encryption)
  based authentication backend.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([] (jwe nil))
  ([opts] (token/jwe-backend opts)))

(defn token
  "Create an instance of the generic token based
  authentication backend.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([] (token nil))
  ([opts] (token/token-backend opts)))

