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

(ns buddy.auth.accessrules
  (:require [buddy.auth :refer [throw-unauthorized]]
            [ring.util.response :as ring]
            [clojure.walk :refer [postwalk]]
            [clout.core :as clout]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Rule Handler Protocol
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IRuleHandlerResponse
  "Protocol for uniform identification on
  success value on rule handler response."
  (success? [_] "Check if a response is a success.")
  (get-value [_] "Get a hander response value."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Rule Handler Response Type
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftype RuleSuccess [v]
  IRuleHandlerResponse
  (success? [_] true)
  (get-value [_] v)

  Object
  (equals [self other]
    (if (instance? RuleSuccess other)
      (= v (.-v other))
      false))

  (toString [self]
    (with-out-str (print [v]))))

(deftype RuleError [v]
  IRuleHandlerResponse
  (success? [_] false)
  (get-value [_] v)

  Object
  (equals [self other]
    (if (instance? RuleError other)
      (= v (.-v other))
      false))

  (toString [self]
    (with-out-str (print [v]))))

(defn success
  "Function that return a success state
  from one access rule handler."
  ([] (RuleSuccess. nil))
  ([v] (RuleSuccess. v)))

(defn error
  "Function that return a failure state
  from one access rule handler."
  ([] (RuleError. nil))
  ([v] (RuleError. v)))

;; Default implementation for IRuleHandlerResponse protocol
;; for nil and any boolean value.

(extend-protocol IRuleHandlerResponse
  nil
  (success? [_] false)
  (get-value [_] nil)

  Boolean
  (success? [v] v)
  (get-value [_] nil))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- compile-rule-handler
  "Receives a rule handler and return a compiled version of it.

  The compiled version of rule handler consists in
  one function that accepts a request as first parameter
  and return the result of the evaluation of it.

  The rule can be a simple function or logical expersion. Logical
  expresion is expressed using a hashmap:

     {:or [f1 f2]}
     {:and [f1 f2]}

  Logical expressions can be nestest as deep as you want:

     {:or [f1 {:and [f2 f3]}]}

  The rule handler as unit of work, should return a
  `success` or `error`. `success` is a simple mark that
  means that handler passes the validation and `error`
  is a mark that means that rule does not pass the
  validation.

  An error mark can return a ring response that will be
  returned to the http client or string message that will
  passed to `on-error` handler if it exists, or returned as
  bad-request response with message as response body.

  Example of success marks:
    true
    (success)

  Example of error marks:
    nil
    false
    (error \"Error msg\")
    (error {:status 400 :body \"Unauthorized\"})
  "
  [rule]
  (postwalk (fn [form]
              (cond
               ;; In this case is a handler
               (fn? form)
               (fn [req] (form req))

               (:or form)
               (fn [req]
                 (let [rules (:or form)
                       evals (map (fn [x] (x req)) rules)
                       accepts (filter success? evals)]
                   (if (seq accepts)
                     (first accepts)
                     (first evals))))

               (:and form)
               (fn [req]
                 (let [rules (:and form)
                       evals (map (fn [x] (x req)) rules)
                       rejects (filter (complement success?) evals)]
                   (if (seq rejects)
                     (first rejects)
                     (first evals))))

               :else form))
            rule))

(defn- compile-access-rule
  "Receives a access rule and return a compiled version of it.

  The plain version of access rule consists in one hash-map with
  with `:uri` and `:handler` keys. `:uri` is a url match syntax
  that will be used for match the url and `:handler` is a rule
  handler.

  Little overview of aspect of access rules:

    [{:uri \"/foo\"
      :handler user-access}
     {:uris [\"/bar\" \"/baz\"]
      :handler admin-access}]

  The clout library (https://github.com/weavejester/clout)
  for matching the `:uri`.

  It also has support for more advanced matching using
  plain regular expressions:

    [{:pattern #\"^/foo$\"
      :handler user-access}

  The compilation process consists in transform the plain version
  in one optimized of it for avoid unnecesary overhead to the
  request process time.

  The compiled version of access rule has very similar format that
  the plain one. The difference is that `:handler` is a compiled
  version, and `:pattern` or `:uri` is replaced by matcher function.

  Little overview of aspect of compiled version of acces rule:

    [{:matcher #<accessrules$compile_access_rule$fn__13092$fn__13095...>
      :handler #<accessrules$compile_rule_handler$fn__14040$fn__14043...>
  "
  [accessrule]
  {:pre [(map? accessrule)]}
  (let [handler (compile-rule-handler (:handler accessrule))
        matcher (cond
                 (:pattern accessrule)
                 (fn [request]
                   (let [pattern (:pattern accessrule)
                         uri (or (:path-info request)
                                 (:uri request))]
                     (boolean (seq (re-matches pattern uri)))))

                 (:uri accessrule)
                 (let [route (clout/route-compile (:uri accessrule))]
                   (fn [request]
                     (boolean (clout/route-matches route request))))

                 (:uris accessrule)
                 (let [routes (mapv clout/route-compile (:uris accessrule))]
                   (fn [request]
                     (boolean (some #(clout/route-matches % request) routes))))

                 :else (fn [request] true))]
    (assoc accessrule
      :matcher matcher
      :handler handler)))

(defn- compile-access-rules
  "Compile a list of access rules.

  For more information, see the docstring
  of `compile-access-rule` function."
  [accessrules]
  (mapv compile-access-rule accessrules))

(defn- match-access-rules
  "Iterates over all access rules and try match each one
  in order. Return a first matched access rule or nil."
  [accessrules request]
  (first (filter (fn [accessrule]
                   (let [matcher (:matcher accessrule)]
                     (matcher request)))
                 accessrules)))

(defn- handle-error
  "Handles the error situation when access rules are
  evaluated in `wrap-access-rules` middleware.

  It receives a hanlder response (anything that rule handler may
  return), a current request and a hashmap passwd to the access
  rule defintion.

  The received response are mandatory satisfies
  IRuleHandlerResponse protocol."
  [response request {:keys [reject-handler on-error redirect]}]
  {:pre [(satisfies? IRuleHandlerResponse response)]}
  (let [val (get-value response)]
    (cond
     (string? redirect)
     (ring/redirect redirect)

     (fn? on-error)
     (on-error request val)

     (ring/response? val)
     val

     (fn? reject-handler)
     (reject-handler request val)

     (string? val)
     (-> (ring/response val)
         (ring/status 400))

     :else
     (throw-unauthorized))))

(defn- apply-matched-access-rule
  "Simple helper that executes the rule handler
  of received access rule and returns the result."
  [match request]
  {:pre [(map? match)
         (contains? match :handler)]}
  (let [handler (:handler match)]
    (handler request)))

(defn wrap-access-rules
  "An ring middleware that helps define access rules for
  ring handler.

  This is a example of access rules list that `wrap-access-rules`
  middleware expects:

      [{:uri \"/foo/*\"
        :handler user-access}
       {:uri \"/bar/*\"
        :handler {:or [user-access admin-access]}}
       {:uri \"/baz/*\"
        :handler {:and [user-access {:or [admin-access operator-access]}]}}]

  All access rules are evaluated in order and stops on first
  match found.

  See docstring of `compile-rule-handler` for documentation
  about rule handlers."
  [handler & [{:keys [policy rules] :or {policy :allow} :as opts}]]
  (when (nil? rules)
    (throw (IllegalArgumentException. "rules should not be empty.")))
  (let [accessrules (compile-access-rules rules)]
    (fn [request]
      (if-let [match (match-access-rules accessrules request)]
        (let [res (apply-matched-access-rule match request)]
          (if (success? res)
           (handler request)
           (handle-error res request (merge opts match))))
        (case policy
          :allow (handler request)
          :reject (handle-error (error nil) request opts))))))

(defn restrict
  "Like `wrap-access-rules` middleware but works as
  decorator. Is intended for use with compojure routing
  library or similar. Example:

    (defn login-ctrl [req] ...)
    (defn admin-ctrl [req] ...)

    (defroutes app
      (ANY \"/login\" [] login-ctrl)
      (GET \"/admin\" [] (restrict admin-ctrl {:handler admin-access ;; Mandatory
                                               :on-error my-reject-handler)

  This decorator allow use same access rules but without
  any url matching algorithm but with disadvantage of
  accoupling your routers code with access rules."
  [handler rule]
  (let [match (compile-access-rule rule)]
    (fn [request]
      (let [rsp (apply-matched-access-rule match request)]
        (if (success? rsp)
         (handler request)
         (handle-error rsp request rule))))))
