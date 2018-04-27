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


(defn sync-async-handler-fn
  "Receives a 1-arity ring handler function and returns a multiple arity ring 
  handler function."
  [handler]
  (fn [request] 
    (handler request))
  (fn [request respond raise] 
    (try (respond (handler request))
      (catch Exception e
        (raise e)))))


(defmacro fn->multi 
  "Takes an anonymous `(fn [request] ...)` declaration of 1-arity and converts it to a multiple arity `fn`,
   supporting both sync and async handler styles."
  [req body]
  {:pre [(= 1 (count req))]}
  `(fn ([~@req] ~body)
       ([~@req respond# raise#]
         (try 
           (respond# ~body)
           (catch Exception e#
             (raise# e#))))))


#_(def f (n->multi [r] (/ 1 r)))

#_(f 1 (partial println "respond")  (partial println "raise"))
#_(clojure.walk/macroexpand-all  '(defn wrap-auth [handler] (n->multi [request] (handler request))))
#_(clojure.pprint/pprint (macroexpand-1  '(fnhandler [request] (+ 1 request))))
