(ns buddy.auth.accessrules-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :as ring]
            [buddy.auth.accessrules :as acr :refer (success error restrict wrap-access-rules)]))

(defn ok [v] (acr/success v))
(defn fail [v] (acr/error v))

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
)

(defn test-handler
  [req]
  (ring/response req))

(deftest restrict-test
  (testing "restrict handler 1"
    (let [handler (restrict test-handler {:handler {:or [ok fail]}})
          rsp     (handler "test")]
      (is (= "test" (:body rsp)))))

  (testing "restrict handler with failure 1"
    (let [handler (restrict test-handler {:handler {:or [fail fail]}})]
      (is (thrown? Exception (handler 1)))))

  (testing "restrict handler with failure 2"
    (let [handler (restrict test-handler {:handler {:or [fail fail]}})
          rsp (handler "Failure message")]
      (is (= "Failure message" (:body rsp)))
      (is (= 400 (:status rsp)))))

  (testing "restrict handlerw with failure and explicit on-error handler"
    (let [handler (restrict test-handler
                            {:handler {:or [fail fail]}
                             :on-error (fn [req val] (ring/response (str "onfail-" val)))})
          rsp     (handler "test")]
      (is (= "onfail-test" (:body rsp)))))

  (testing "restrict handlerw with failure and redirect"
    (let [handler (restrict test-handler
                            {:handler {:or [fail fail]}
                             :redirect "/foobar"})
          rsp     (handler "test")]
      (is (= 302 (:status rsp)))
      (is (= "/foobar" (get-in rsp [:headers "Location"])))))
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
           {:uris ["/path3" "/path0"]
            :handler {:and [fail ok]}}]})

(defn on-error
  [req val]
  (-> (ring/response val)
      (ring/status 400)))


(def handler1
  (wrap-access-rules test-handler
                     (assoc params1 :policy :reject)))

(def handler2
  (wrap-access-rules test-handler
                     (assoc params1
                       :policy :reject
                       :on-error on-error)))

(def handler3
  (wrap-access-rules test-handler
                     (assoc params2 :policy :reject)))

(deftest wrap-access-rules-test
  (testing "check access rules 1"
    (let [rsp (handler1 {:uri "/path1"})]
      (is (= {:uri "/path1"} (:body rsp)))))

  (testing "check access rules 2"
    (let [rsp (handler1 {:uri "/path2"})]
      (is (= {:uri "/path2"} (:body rsp)))))

  (testing "check access rules 3"
    (is (thrown? Exception (handler1 {:uri "/path3"}))))

  (testing "check access rules 4"
    (is (thrown? Exception (handler1 {:uri "/path4"}))))

  (testing "check access rules 5"
    (let [rsp (handler2 {:uri "/path3"})]
      (is (= 400 (:status rsp)))
      (is (= {:uri "/path3"} (:body rsp)))))

  (testing "check access rules 6"
    (let [rsp (handler2 {:uri "/path4"})]
      (is (= 400 (:status rsp)))
      (is (= nil (:body rsp)))))

  ;; Clout format

  (testing "check access rules 1"
    (let [rsp (handler3 {:uri "/path1"})]
      (is (= {:uri "/path1"} (:body rsp)))))

  (testing "check access rules 2"
    (let [rsp (handler3 {:uri "/path2"})]
      (is (= {:uri "/path2"} (:body rsp)))))

  (testing "check access rules 3"
    (is (thrown? Exception (handler3 {:uri "/path3"}))))

  (testing "check access rules 4"
    (is (thrown? Exception (handler3 {:uri "/path4"}))))
)

(defn method-handler [type type-param allowed]
  (wrap-access-rules
   test-handler
   {:rules [{type type-param
             :handler ok
             :request-method allowed}]
    :policy :reject}))

(deftest wrap-access-rules-method-test
  (let [allowed {:uri "/comments/1" :request-method :get}
        forbidden (assoc allowed :request-method :delete)]

    (testing "access rule pattern"
      (let [method-handler (partial method-handler :pattern #"/comments/\d+")]

        (testing "with keyword as allowed method"
          (let [handler (method-handler :get)]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? Exception (handler forbidden)))))

        (testing "with set of keywords as allowed method"
          (let [handler (method-handler #{:get})]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? Exception (handler forbidden)))))

        (testing "with nil as allowed request method"
          (let [handler (method-handler nil)]
            (is (= (:body (handler allowed)) allowed))))))

    (testing "access rule uri"
      (let [method-handler (partial method-handler :uri "/comments/:id")]

        (testing "with keyword as allowed method"
          (let [handler (method-handler :get)]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? Exception (handler forbidden)))))

        (testing "with set of keywords as allowed method"
          (let [handler (method-handler #{:get})]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? Exception (handler forbidden)))))

        (testing "with nil as allowed request method"
          (let [handler (method-handler nil)]
            (is (= (:body (handler allowed)) allowed))))))

    (testing "access rule uris"
      (let [method-handler (partial method-handler :uris ["/comments/:id"])]

        (testing "with keyword as allowed method"
          (let [handler (method-handler :get)]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? Exception (handler forbidden)))))

        (testing "with set of keywords as allowed method"
          (let [handler (method-handler #{:get})]
            (is (= (:body (handler allowed)) allowed))
            (is (thrown? Exception (handler forbidden)))))

        (testing "with nil as allowed request method"
          (let [handler (method-handler nil)]
            (is (= (:body (handler allowed)) allowed))))))))
