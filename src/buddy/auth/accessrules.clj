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

(ns buddy.auth.accessrules
  "Access Rules system for ring based applications."
  (:require [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.http :as http]
            [buddy.auth.fnutils :refer [fn->multi]]
            [clojure.walk :refer [postwalk]]
            [clout.core :as clout]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Rule Handler Protocol
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IRuleHandlerResponse
  "Abstraction for uniform handling of rule handler return values.
  It comes with default implementation for nil and boolean types."
  (success? [_] "Check if a response is a success.")
  (get-value [_] "Get a handler response value."))

(extend-protocol IRuleHandlerResponse
  nil
  (success? [_] false)
  (get-value [_] nil)

  Boolean
  (success? [v] v)
  (get-value [_] nil))

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

(alter-meta! #'->RuleSuccess assoc :private true)
(alter-meta! #'->RuleError assoc :private true)

(defn success
  "Function that returns a success state
  from one access rule handler."
  ([] (RuleSuccess. nil))
  ([v] (RuleSuccess. v)))

(defn error
  "Function that returns a failure state
  from one access rule handler."
  ([] (RuleError. nil))
  ([v] (RuleError. v)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn compile-rule-handler
  "Receives a rule handler and returns a compiled version of it.

  The compiled version of a rule handler consists of
  one function that accepts a request as first parameter
  and returns the result of the evaluation of it.

  The rule can be a simple function or logical expression. Logical
  expression is expressed using a hashmap:

      {:or [f1 f2]}
      {:and [f1 f2]}

  Logical expressions can be nested as deep as you want:

      {:or [f1 {:and [f2 f3]}]}

  The rule handler as unit of work, should return a
  `success` or `error`. `success` is a simple mark that
  means that handler passes the validation and `error`
  is a mark that means that rule does not pass the
  validation.

  An error mark can return a ring response that will be
  returned to the http client or string message that will be
  passed to `on-error` handler if it exists, or returned as
  bad-request response with message as response body.

  Example of success marks:

  - `true`
  - `(success)`

  Example of error marks:

  - `nil`
  - `false`
  - `(error \"Error msg\")`
  - `(error {:status 400 :body \"Unauthorized\"})`
  "
  [rule]
  (postwalk (fn [form]
              (cond
               ;; In this case is a handler
               (fn? form)
               (fn->multi [req] (form req))

               (:or form)
               (fn->multi [req]
                 (let [rules (:or form)
                       evals (map (fn [x] (x req)) rules)
                       accepts (filter success? evals)]
                   (if (seq accepts)
                     (first accepts)
                     (last evals))))

               (:and form)
               (fn->multi [req]
                 (let [rules (:and form)
                       evals (map (fn [x] (x req)) rules)
                       rejects (filter (complement success?) evals)]
                   (if (seq rejects)
                     (first rejects)
                     (first evals))))

               :else form))
            rule))

(defn- matches-request-method
  "Match the :request-method of `request` against `allowed` HTTP
  methods. `allowed` can be a keyword, a set of keywords or nil."
  [request allowed]
  (let [actual (:request-method request)]
    (cond
      (keyword? allowed)
      (= actual allowed)

      (set? allowed)
      (or (empty? allowed)
          (contains? allowed actual))

      :else true)))

(defn  compile-access-rule
  "Receives an access rule and returns a compiled version of it.

  The plain version of access rule consists of one hash-map with
  with `:uri` and `:handler` keys. `:uri` is a url match syntax
  that will be used for matching the url and `:handler` is a rule
  handler.

  Little overview of aspect of access rules:

      [{:uri \"/foo\"
        :handler user-access}
       {:uris [\"/bar\" \"/baz\"]
        :handler admin-access}]

  The clout library (https://github.com/weavejester/clout)
  for matching the `:uri`.

  It also has support for more advanced matching using plain
  regular expressions, which are matched against the full
  request uri:

      [{:pattern #\"^/foo$\"
        :handler user-access}

  An access rule can also match against certain HTTP methods, by using
  the `:request-method` option. `:request-method` can be a keyword or
  a set of keywords.

      [{:pattern #\"^/foo$\"
        :handler user-access
        :request-method :get}

  The compilation process consists in transforming the plain version
  into an optimized one in order to avoid unnecessary overhead to the
  request process time.

  The compiled version of access rule has a very similar format with
  the plain one. The difference is that `:handler` is a compiled
  version, and `:pattern` or `:uri` is replaced by matcher function.

  Little overview of aspect of compiled version of acces rule:

      [{:matcher #<accessrules$compile_access_rule$fn__13092$fn__13095...>
        :handler #<accessrules$compile_rule_handler$fn__14040$fn__14043...>
  "
  [accessrule]
  {:pre [(map? accessrule)]}
  (let [request-method (:request-method accessrule)
        handler (compile-rule-handler (:handler accessrule))
        matcher (cond
                  (:pattern accessrule)
                  (fn->multi [request]
                    (let [pattern (:pattern accessrule)
                          uri (:uri request)]
                      (when (and (matches-request-method request request-method)
                                 (seq (re-matches pattern uri)))
                        {})))

                  (:uri accessrule)
                  (let [route (clout/route-compile (:uri accessrule))]
                    (fn->multi [request]
                      (let [match-params (clout/route-matches route request)]
                        (when (and (matches-request-method request request-method) match-params)
                          match-params))))

                  (:uris accessrule)
                  (let [routes (mapv clout/route-compile (:uris accessrule))]
                    (fn->multi [request]
                      (let [match-params (->> (map #(clout/route-matches % request) routes)
                                              (filter identity)
                                              (first))]
                        (when (and (matches-request-method request request-method) match-params)
                          match-params))))

                  :else (fn->multi [request] {}))]
    (assoc accessrule
           :matcher matcher
           :handler handler)))

(defn compile-access-rules
  "Compile a list of access rules.

  For more information, see the docstring
  of `compile-access-rule` function."
  [accessrules]
  (mapv compile-access-rule accessrules))

(defn- match-access-rules
  "Iterates over all access rules and try to match each one
  in order. Return the first matched access rule or nil."
  [accessrules request]
  (reduce (fn [acc accessrule]
            (let [matcher (:matcher accessrule)
                  match-result (matcher request)]
              (when match-result
                (reduced (assoc accessrule :match-params match-result)))))
          nil
          accessrules))

(defn handle-error
  "Handles the error situation when access rules are
  evaluated in `wrap-access-rules` middleware.

  It receives a handler response (anything that rule handler may
  return), a current request and a hashmap passwd to the access
  rule definition.

  The received response has to satisfy the
  IRuleHandlerResponse protocol."
  {:no-doc true}
  ([response request {:keys [reject-handler on-error redirect]}]
   {:pre [(satisfies? IRuleHandlerResponse response)]}
   (let [val (get-value response)]
     (cond
       (string? redirect)
       (http/redirect redirect)

       (fn? on-error)
       (on-error request val)

       (http/response? val)
       val

       (fn? reject-handler)
       (reject-handler request val)

       (string? val)
       (http/response val 400)

       :else
       (throw-unauthorized))))
  ([response request rule respond raise]
   (try
     (let [err (handle-error response request rule)]
       (respond err))
     (catch Exception e
       (raise e)))))

(defn- apply-matched-access-rule
  "Simple helper that executes the rule handler
  of received access rule and returns the result."
  [match request]
  {:pre [(map? match)
         (contains? match :handler)]}
  (let [handler (:handler match)
        params  (:match-params match)]
    (-> request
        (assoc :match-params params)
        (handler))))

(defn wrap-access-rules
  "A ring middleware that helps to define access rules for
  ring handler.

  This is an example of access rules list that `wrap-access-rules`
  middleware expects:

      [{:uri \"/foo/*\"
        :handler user-access}
       {:uri \"/bar/*\"
        :handler {:or [user-access admin-access]}}
       {:uri \"/baz/*\"
        :handler {:and [user-access {:or [admin-access operator-access]}]}}]

  All access rules are evaluated in order and the process stops when
  a match is found.

  See docstring of `compile-rule-handler` for documentation
  about rule handlers."
  [handler & [{:keys [policy rules] :or {policy :allow} :as opts}]]
  (when (nil? rules)
    (throw (IllegalArgumentException. "rules should not be empty.")))
  (let [accessrules (compile-access-rules rules)]
    (fn
      ([request]
       (if-let [match (match-access-rules accessrules request)]
         (let [res (apply-matched-access-rule match request)]
           (if (success? res)
             (handler request)
             (handle-error res request (merge opts match))))
         (case policy
           :allow (handler request)
           :reject (handle-error (error nil) request opts))))
      ([request respond raise]
       (if-let [match (match-access-rules accessrules request)]
         (let [res (apply-matched-access-rule match request)]
           (if (success? res)
             (handler request respond raise)
             (handle-error res request (merge opts match) respond raise)))
         (case policy
           :allow (handler request respond raise)
           :reject (handle-error (error nil) request opts respond raise)))))))

(defn restrict
  "Like `wrap-access-rules` middleware but works as
  decorator. It is intended to be used with compojure routing
  library or similar. Example:

      (defn login-ctrl [req] ...)
      (defn admin-ctrl [req] ...)

      (defroutes app
        (ANY \"/login\" [] login-ctrl)
        (GET \"/admin\" [] (restrict admin-ctrl {:handler admin-access ;; Mandatory
                                                 :on-error my-reject-handler)

  This decorator allows using the same access rules but without
  any url matching algorithm, however it has the disadvantage of
  accoupling your routers code with access rules."
  [handler rule]
  (let [match (compile-access-rule rule)]
    (fn
      ([request]
       (let [rsp (apply-matched-access-rule match request)]
         (if (success? rsp)
           (handler request)
           (handle-error rsp request rule))))
      ([request respond raise]
       (let [rsp (apply-matched-access-rule match request)]
         (if (success? rsp)
           (handler request respond raise)
           (handle-error rsp request rule respond raise)))))))
