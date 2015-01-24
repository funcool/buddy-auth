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

(ns buddy.auth.utils
  (:require [cuerdas.core :as str]
            [clojure.walk :refer [postwalk]]))

(defn lowercase-headers
  [headers]
  (postwalk (fn [form]
              (if (vector? form)
                (cond
                  (string? (first form)) [(str/lower (first form)) (second form)]
                  (keyword? (first form)) [(keyword (str/lower (name (first form)))) (second form)]
                  :else form)
                form))
            headers))
