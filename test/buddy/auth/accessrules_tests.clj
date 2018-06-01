(ns buddy.auth.accessrules-tests
  (:require [clojure.test :refer :all]
            [buddy.auth.http :as http]
            [buddy.auth.accessrules :as acr :refer (success error restrict wrap-access-rules)]))

(defn ok [v] (acr/success v))
(defn fail [v]
  (acr/error (if (and (map? v) (:msg v)) (:msg v) v)))

(defn ok2 [v] true)
(defn fail2 [v] false)

(deftest compile-rule-handler
  (testing "compile access rules 1"
    (let [rule (#'acr/compile-rule-handler ok)
          result (rule 1)]
      (is (= (success 1) result))))

  (testing "compile access rules 2"
    (let [rule (#'acr/compile-rule-handler {:or [ok fail]})
          result (rule 1)]
      (is (= (success 1) result))))

  (testing "compile access rules 3"
    (let [rule (#'acr/compile-rule-handler {:and [ok fail]})
          result (rule 1)]
      (is (= (error 1) result))))

  (testing "compile access rules 4"
    (let [rule (#'acr/compile-rule-handler {:or [fail fail {:and [ok ok]}]})
          result (rule 1)]
      (is (= (success 1) result))))

  (testing "compile access rules 5"
    (let [rule (#'acr/compile-rule-handler {:and [ok ok]})
          result (rule 1)]
      (is (= (success 1) result))))

  (testing "compile access rules 6"
    (let [rule (#'acr/compile-rule-handler {:and [ok2 ok2]})
          result (rule 1)]
      (is (= true result))))

  (testing "compile access rules 7"
    (let [rule (#'acr/compile-rule-handler {:or [fail2 ok2]})
          result (rule 1)]
      (is (= true result))))

  (testing "compile access rules 8"
    (let [rule (#'acr/compile-rule-handler {:or [fail2 fail]})
          result (rule 1)]
      (is (= (error 1) result))))
)

(defn test-handler
  [req]
  (http/response req))

(defn async-test-handler
  [req respond _]
  (respond (test-handler req)))

(deftest restrict-test
  (testing "restrict handler 1"
    (let [handler (restrict test-handler {:handler {:or [ok fail]}})
          rsp     (handler {:foo "bar"})]
      (is (= {:foo "bar"} (:body rsp)))))

  (testing "restrict async handler 1"
    (let [handler (restrict async-test-handler {:handler {:or [ok fail]}})
          req     {:foo "bar"}
          rsp     (promise)
          ex      (promise)]
      (handler req rsp ex)
      (is (= {:foo "bar"} (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "restrict handler with failure 1"
    (let [handler (restrict test-handler {:handler {:or [fail fail]}})]
      (is (thrown? clojure.lang.ExceptionInfo (handler {:foo "bar"})))))

  (testing "restrict async handler with failure 1"
    (let [handler (restrict async-test-handler {:handler {:or [fail fail]}})
          req     {:foo "bar"}
          rsp     (promise)
          ex      (promise)]
      (handler req rsp ex)
      (is (instance? clojure.lang.ExceptionInfo @ex))
      (is (not (realized? rsp)))))

  (testing "restrict handler with failure 2"
    (let [handler (restrict test-handler {:handler {:or [fail fail]}})
          rsp (handler {:msg "Failure message"})]
      (is (= "Failure message" (:body rsp)))
      (is (= 400 (:status rsp)))))

  (testing "restrict async handler with failure 2"
    (let [handler (restrict async-test-handler {:handler {:or [fail fail]}})
          req     {:msg "Failure message"}
          rsp     (promise)
          ex      (promise)]
      (handler req rsp ex)
      (is (= "Failure message" (:body @rsp)))
      (is (= 400 (:status @rsp)))
      (is (not (realized? ex)))))

  (testing "restrict handlerw with failure and explicit on-error handler"
    (let [handler (restrict test-handler
                            {:handler {:or [fail fail]}
                             :on-error (fn [req val] (http/response (str "onfail-" val)))})
          rsp     (handler {:msg "test"})]
      (is (= "onfail-test" (:body rsp)))))

  (testing "restrict async handlerw with failure and explicit on-error handler"
    (let [handler (restrict async-test-handler
                            {:handler {:or [fail fail]}
                             :on-error (fn [req val] (http/response (str "onfail-" val)))})
          req     {:msg "test"}
          rsp     (promise)
          ex      (promise)]
      (handler req rsp ex)
      (is (= "onfail-test" (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "restrict handlerw with failure and redirect"
    (let [handler (restrict test-handler
                            {:handler {:or [fail fail]}
                             :redirect "/foobar"})
          rsp     (handler {:msg "test"})]
      (is (= 302 (:status rsp)))
      (is (= "/foobar" (get-in rsp [:headers "Location"])))))

  (testing "restrict async handlerw with failure and redirect"
    (let [handler (restrict async-test-handler
                            {:handler {:or [fail fail]}
                             :redirect "/foobar"})
          req     {:msg "test"}
          rsp     (promise)
          ex      (promise)]
      (handler req rsp ex)
      (is (= 302 (:status @rsp)))
      (is (= "/foobar" (get-in @rsp [:headers "Location"])))
      (is (not (realized? ex)))))
)

(def params1
  {:rules [{:pattern #"^/path1$"
            :handler {:or [ok fail]}}
           {:pattern #"^/path2$"
            :handler ok}
           {:pattern #"^/path3$"
            :handler {:and [fail ok]}}]})

(def params2
  {:rules [{:uri "/path1"
            :handler {:or [ok fail]}}
           {:uri "/path2"
            :handler ok}
           {:uris ["/path3" "/path0" "/path/:param"]
            :handler {:and [fail ok]}}]})

(defn on-error
  [req val]
  (http/response val 400))

(def handler1
  (wrap-access-rules test-handler
                     (assoc params1 :policy :reject)))

(def async-handler1
  (wrap-access-rules async-test-handler
                     (assoc params1 :policy :reject)))

(def handler2
  (wrap-access-rules test-handler
                     (assoc params1
                       :policy :reject
                       :on-error on-error)))

(def async-handler2
  (wrap-access-rules async-test-handler
                     (assoc params1
                            :policy :reject
                            :on-error on-error)))

(def handler3
  (wrap-access-rules test-handler
                     (assoc params2 :policy :reject)))

(def async-handler3
  (wrap-access-rules async-test-handler
                     (assoc params2 :policy :reject)))

(deftest wrap-access-rules-test
  (testing "check access rules 1"
    (let [rsp (handler1 {:uri "/path1"})]
      (is (= {:uri "/path1"} (:body rsp)))))

  (testing "check access rules 1 async"
    (let [req {:uri "/path1"}
          rsp (promise)
          ex  (promise)]
      (async-handler1 req rsp ex)
      (is (= {:uri "/path1"} (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "check access rules 2"
    (let [rsp (handler1 {:uri "/path2"})]
      (is (= {:uri "/path2"} (:body rsp)))))

  (testing "check access rules 2 async"
    (let [req {:uri "/path2"}
          rsp (promise)
          ex  (promise)]
      (async-handler1 req rsp ex)
      (is (= {:uri "/path2"} (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "check access rules 3"
    (is (thrown? clojure.lang.ExceptionInfo (handler1 {:uri "/path3"}))))

  (testing "check access rules 3 async"
    (let [req {:uri "/path3"}
          rsp (promise)
          ex  (promise)]
      (async-handler1 req rsp ex)
      (is (instance? clojure.lang.ExceptionInfo @ex))
      (is (not (realized? rsp)))))

  (testing "check access rules 4"
    (is (thrown? clojure.lang.ExceptionInfo (handler1 {:uri "/path4"}))))

  (testing "check access rules 4 async"
    (let [req {:uri "/path4"}
          rsp (promise)
          ex  (promise)]
      (async-handler1 req rsp ex)
      (is (instance? clojure.lang.ExceptionInfo @ex))
      (is (not (realized? rsp)))))

  (testing "check access rules 5"
    (let [rsp (handler2 {:uri "/path3"})]
      (is (= 400 (:status rsp)))
      (is (= {:uri "/path3" :match-params {}} (:body rsp)))))

  (testing "check access rules 5 async"
    (let [req {:uri "/path3"}
          rsp (promise)
          ex  (promise)]
      (async-handler2 req rsp ex)
      (is (= 400 (:status @rsp)))
      (is (= {:uri "/path3" :match-params {}} (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "check access rules 6"
    (let [rsp (handler2 {:uri "/path4"})]
      (is (= 400 (:status rsp)))
      (is (= nil (:body rsp)))))

  (testing "check access rules 6 async"
    (let [req {:uri "/path4"}
          rsp (promise)
          ex  (promise)]
      (async-handler2 req rsp ex)
      (is (= 400 (:status @rsp)))
      (is (= nil (:body @rsp)))
      (is (not (realized? ex)))))

  ;; Clout format

  (testing "check access rules 1"
    (let [rsp (handler3 {:uri "/path1"})]
      (is (= {:uri "/path1"} (:body rsp)))))

  (testing "check access rules 1 async"
    (let [req {:uri "/path1"}
          rsp (promise)
          ex  (promise)]
      (async-handler3 req rsp ex)
      (is (= {:uri "/path1"} (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "check access rules 2"
    (let [rsp (handler3 {:uri "/path2"})]
      (is (= {:uri "/path2"} (:body rsp)))))

  (testing "check access rules 2 async"
    (let [req {:uri "/path2"}
          rsp (promise)
          ex  (promise)]
      (async-handler3 req rsp ex)
      (is (= {:uri "/path2"} (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "check access rules 3"
    (let [rsp (handler3 {:uri "/path/foobar" :body "Fail" :status 400 :headers {}})]
      (is (= 400 (:status rsp)))
      (is (= {:param "foobar"} (:match-params rsp)))
      (is (= "Fail" (:body rsp)))))

  (testing "check access rules 3 async"
    (let [req {:uri "/path/foobar" :body "Fail" :status 400 :headers {}}
          rsp (promise)
          ex  (promise)]
      (async-handler3 req rsp ex)
      (is (= 400 (:status @rsp)))
      (is (= {:param "foobar"} (:match-params @rsp)))
      (is (= "Fail" (:body @rsp)))
      (is (not (realized? ex)))))

  (testing "check access rules 4"
    (is (thrown? clojure.lang.ExceptionInfo (handler3 {:uri "/path3"}))))

  (testing "check access rules 4 async"
    (let [req {:uri "/path3"}
          rsp (promise)
          ex  (promise)]
      (async-handler3 req rsp ex)
      (is (instance? clojure.lang.ExceptionInfo @ex))
      (is (not (realized? rsp)))))

  (testing "check access rules 5"
    (is (thrown? clojure.lang.ExceptionInfo (handler3 {:uri "/path4"}))))

  (testing "check access rules 5 async"
    (let [req {:uri "/path4"}
          rsp (promise)
          ex  (promise)]
      (async-handler3 req rsp ex)
      (is (instance? clojure.lang.ExceptionInfo @ex))
      (is (not (realized? rsp)))))
)

(defn method-handler [type type-param allowed]
  (wrap-access-rules
   test-handler
   {:rules [{type type-param
             :handler ok
             :request-method allowed}]
    :policy :reject}))

(defn async-method-handler [type type-param allowed]
  (wrap-access-rules
   async-test-handler
   {:rules [{type type-param
             :handler ok
             :request-method allowed}]
    :policy :reject}))

(deftest wrap-access-rules-method-test
  (let [allowed {:uri "/comments/1" :request-method :get}
        forbidden (assoc allowed :request-method :delete)]

    (testing "access rule pattern"
      (let [method-handler (partial method-handler :pattern #"/comments/\d+")
            async-method-handler (partial async-method-handler
                                          :pattern #"/comments/\d+")]

        (testing "with keyword as allowed method"
          (let [handler (method-handler :get)]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? clojure.lang.ExceptionInfo (handler forbidden)))))

        (testing "async with keyword as allowed method"
          (let [handler (async-method-handler :get)]
            (let [rsp (promise)
                  ex  (promise)]
              (handler allowed rsp ex)
              (is (= (:body @rsp) allowed))
              (is (not (realized? ex))))
            (let [rsp (promise)
                  ex  (promise)]
              (handler forbidden rsp ex)
              (is (instance? clojure.lang.ExceptionInfo @ex))
              (is (not (realized? rsp))))))

        (testing "with set of keywords as allowed method"
          (let [handler (method-handler #{:get})]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? clojure.lang.ExceptionInfo (handler forbidden)))))

        (testing "async with set of keywords as allowed method"
          (let [handler (async-method-handler #{:get})]
            (let [rsp (promise)
                  ex  (promise)]
              (handler allowed rsp ex)
              (is (= (:body @rsp) allowed))
              (is (not (realized? ex))))
            (let [rsp (promise)
                  ex  (promise)]
              (handler forbidden rsp ex)
              (is (instance? clojure.lang.ExceptionInfo @ex))
              (is (not (realized? rsp))))))

        (testing "with nil as allowed request method"
          (let [handler (method-handler nil)]
            (is (= (:body (handler allowed)) allowed))))

        (testing "async with nil as allowed request method"
          (let [handler (async-method-handler nil)
                rsp     (promise)
                ex      (promise)]
            (handler allowed rsp ex)
            (is (= (:body @rsp) allowed))
            (is (not (realized? ex)))))))

    (testing "access rule uri"
      (let [method-handler (partial method-handler :uri "/comments/:id")
            async-method-handler (partial async-method-handler
                                          :uri "/comments/:id")]

        (testing "with keyword as allowed method"
          (let [handler (method-handler :get)]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? clojure.lang.ExceptionInfo (handler forbidden)))))

        (testing "async with keyword as allowed method"
          (let [handler (async-method-handler :get)]
            (let [rsp (promise)
                  ex  (promise)]
              (handler allowed rsp ex)
              (is (= (:body @rsp) allowed))
              (is (not (realized? ex))))
            (let [rsp (promise)
                  ex  (promise)]
              (handler forbidden rsp ex)
              (is (instance? clojure.lang.ExceptionInfo @ex))
              (is (not (realized? rsp))))))

        (testing "with set of keywords as allowed method"
          (let [handler (method-handler #{:get})]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? clojure.lang.ExceptionInfo (handler forbidden)))))

        (testing "async with set of keywords as allowed method"
          (let [handler (async-method-handler #{:get})]
            (let [rsp (promise)
                  ex  (promise)]
              (handler allowed rsp ex)
              (is (= (:body @rsp) allowed))
              (is (not (realized? ex))))
            (let [rsp (promise)
                  ex  (promise)]
              (handler forbidden rsp ex)
              (is (instance? clojure.lang.ExceptionInfo @ex))
              (is (not (realized? rsp))))))

        (testing "with nil as allowed request method"
          (let [handler (method-handler nil)]
            (is (= (:body (handler allowed)) allowed))))

        (testing "async with nil as allowed request method"
          (let [handler (async-method-handler nil)
                rsp     (promise)
                ex      (promise)]
            (handler allowed rsp ex)
            (is (= (:body @rsp) allowed))
            (is (not (realized? ex)))))))

    (testing "access rule uris"
      (let [method-handler (partial method-handler :uris ["/comments/:id"])
            async-method-handler (partial async-method-handler
                                          :uris ["/comments/:id"])]

        (testing "with keyword as allowed method"
          (let [handler (method-handler :get)]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? clojure.lang.ExceptionInfo (handler forbidden)))))

        (testing "async with keyword as allowed method"
          (let [handler (async-method-handler :get)]
            (let [rsp (promise)
                  ex  (promise)]
              (handler allowed rsp ex)
              (is (= (:body @rsp) allowed))
              (is (not (realized? ex))))
            (let [rsp (promise)
                  ex  (promise)]
              (handler forbidden rsp ex)
              (is (instance? clojure.lang.ExceptionInfo @ex))
              (is (not (realized? rsp))))))

        (testing "with set of keywords as allowed method"
          (let [handler (method-handler #{:get})]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? clojure.lang.ExceptionInfo (handler forbidden)))))

        (testing "async with set of keywords as allowed method"
          (let [handler (async-method-handler #{:get})]
            (let [rsp (promise)
                  ex  (promise)]
              (handler allowed rsp ex)
              (is (= (:body @rsp) allowed))
              (is (not (realized? ex))))
            (let [rsp (promise)
                  ex  (promise)]
              (handler forbidden rsp ex)
              (is (instance? clojure.lang.ExceptionInfo @ex))
              (is (not (realized? rsp))))))

        (testing "with nil as allowed request method"
          (let [handler (method-handler nil)]
            (is (= (:body (handler allowed)) allowed))))

        (testing "async with nil as allowed request method"
          (let [handler (async-method-handler nil)
                rsp     (promise)
                ex      (promise)]
            (handler allowed rsp ex)
            (is (= (:body @rsp) allowed))
            (is (not (realized? ex)))))))))
