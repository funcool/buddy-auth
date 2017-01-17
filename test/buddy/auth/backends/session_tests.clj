(ns buddy.auth.backends.session-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends :as backends]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-request
  ([] {:session {}})
  ([id] {:session {:identity {:userid 1}}}))

(def backend (backends/session))
(def backend-with-authfn (backends/session {:authfn (constantly ::authorized)}))

(deftest session-backend-test
  (testing "Simple backend authentication 01"
    (let [handler (wrap-authentication identity backend)
          request (make-request 1)
          response (handler request)]
      (is (= (:identity response) {:userid 1}))))

  (testing "Simple backend authentication 02"
    (let [handler (wrap-authentication identity backend)
          request (make-request)
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Handle unauthenticated unauthorized requests without specifying unauthorized handler"
    (let [handler (-> (fn [req] (throw-unauthorized "FooMsg"))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request)
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Handle unauthorized requests specifying unauthorized handler"
    (let [onerror (fn [request metadata] {:body "" :status 3000})
          backend (backends/session {:unauthorized-handler onerror})
          handler (-> (fn [req] (throw-unauthorized "FooMsg"))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request)
          response (handler request)]
      (is (= (:status response) 3000))))

  (testing "Handle authenticated unauthorized requests without specifying unauthorized handler"
    (let [handler (-> (fn [req] (throw-unauthorized "FooMsg"))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request 1)
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Uses custom authfn when provided"
    (let [handler (wrap-authentication identity backend-with-authfn)
          request (make-request 1)
          response (handler request)]
      (is (= ::authorized (:identity response))))))
