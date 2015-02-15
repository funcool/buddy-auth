(ns buddy.auth.backends.token-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response?]]
            [buddy.core.codecs :refer :all]
            [buddy.sign.jws :as jws]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends.token :refer (parse-authorization-header
                                               jws-backend
                                               token-backend)]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(def secret-key "test-secret-key")

(defn authfn
  [request token]
  (let [data {:token1 {:userid 1}
              :token2 {:userid 2}}]
    (get data (keyword token))))

(defn make-request
  ([] {})
  ([token]
   (let [header (format "Token %s" token)]
     {:headers {"authorization" header}})))

(deftest token-parse-test
  (testing "Parse authorization header"
    (let [request (make-request "foo")
          parsed  (parse-authorization-header request "Token")]
      (is (= parsed "foo"))))

  (testing "Parse authorization header different header name yields nil"
    (let [parsed (parse-authorization-header (make-request "foo") "MyToken")]
     (is (= parsed nil)))))

(defn make-jws-token
  ([id] (make-jws-token id secret-key))
  ([id secret]
   (jws/sign {:userid 1} secret)))

(defn make-jws-request
  ([id] (make-jws-request id secret-key))
  ([id secret]
   (let [header (->> (make-jws-token id secret)
                     (format "Token %s"))]
     {:headers {"authorization" header}})))

(def jbackend (jws-backend {:secret secret-key}))

(deftest jws-backend-test
  (testing "Jws token backend authentication"
    (let [request (make-jws-request 1)
          handler (wrap-authentication identity jbackend)
          response (handler request)]
      (is (= (:identity response) {:userid 1}))))

  (testing "Jws token backend authentication with wrong key yields nil"
    (let [request (make-jws-request 1 "wrong-key")
          handler (wrap-authentication identity jbackend)
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Jws token backend authentication with no token yields nil"
    (let [request {}
          handler (wrap-authentication identity jbackend)
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Jws token authorizaton with wrong key yields 401"
    (let [request (make-jws-request 1 "wrong-key")
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jbackend)
                      (wrap-authentication jbackend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Jws token authorization - authenticated but unathorized thrown yields 403"
    (let [request (make-jws-request 1)
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jbackend)
                      (wrap-authentication jbackend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Jws token unathorized - unauth handler called when provided"
    (let [request (make-jws-request 1 "wrong-key")
          onerror (fn [_ _] {:status 3000})
          backend (jws-backend {:secret secret-key
                                :unauthorized-handler onerror})
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000)))))


(def backend (token-backend {:authfn authfn}))

(deftest token-backend-test
  (testing "Basic token backend authentication 01"
    (let [request (make-request "token1")
          handler (wrap-authentication #(:identity %) backend)
          response (handler request)]
      (is (= response {:userid 1}))))

  (testing "Basic token backend authentication 02"
    (let [request (make-request "token3")
          handler (wrap-authentication #(:identity %) backend)
          response (handler request)]
      (is (= response nil))))

  (testing "Token backend with unauthorized requests 1"
    (let [request (make-request "token1")
          handler (-> (fn [request] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Token backend with unauthorized requests 2"
    (let [request (make-request "token3")
          handler (-> (fn [request] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Token backend with unauthorized requests 3"
    (let [request (make-request "token3")
          onerror (fn [_ _] {:status 3000})
          backend (token-backend {:authfn authfn
                                  :unauthorized-handler onerror})
          handler (-> (fn [request] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
        (is (= (:status response) 3000)))))


