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

(ns buddy.auth.fnutils
  "Utility to reuse 1-arity handlers into 3-arity handlers for async support")

(defmacro fn->multi 
  "Replaces an anonymous `(fn [request] ...)` declaration of arity-1 and converts it to a multiple arity `fn`
   (arity-1 and arity-3), supporting both sync and async handler styles.
  
  Instead of declaring an anonymous function `(fn [handler] ...)`, replace the `fn` with the macro:
  `(fn->multi [handler] ...)`"
  [req body]
  {:pre [(= 1 (count req))]}
  `(fn ([~@req] ~body)
       ([~@req respond# raise#]
         (try 
           (respond# ~body)
           (catch Exception e#
             (raise# e#))))))
