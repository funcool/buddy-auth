(ns buddy.auth.backends.token-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.core.codecs :refer :all]
            [buddy.sign.generic :as s]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends.token :refer (parse-authorization-header
                                               signed-token-backend
                                               token-backend)]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(def secret-key "test-secret-key")

(defn authfn
  [request token]
  (let [data {:token1 {:userid 1}
              :token2 {:userid 2}}]
    (get data (keyword token))))

(defn make-signed-token
  ([id] (make-signed-token id secret-key))
  ([id secret]
   (s/dumps {:userid 1} secret)))

(defn make-signed-request
  ([] {})
  ([id] (make-signed-request id secret-key))
  ([id secret]
   (let [header (->> (make-signed-token id secret)
                     (format "Token %s"))]
     {:headers {"Authorization" header}})))

(defn make-request
  ([] {})
  ([token]
   (let [header (format "Token %s" token)]
     {:headers {"Authorization" header}})))

(deftest token-parse-test
  (testing "Parse authorization header"
    (let [request (make-request "foo")
          parsed  (parse-authorization-header request)]
      (is (= parsed "foo")))))

(def sbackend (signed-token-backend {:privkey secret-key}))

(deftest signed-token-backend-test
  (testing "Signed token backend authentication"
    (let [request (make-signed-request 1)
          handler (wrap-authentication identity sbackend)
          response (handler request)]
      (is (= (:identity response) {:userid 1}))))

  (testing "Signed token backend wrong authentication"
    (let [request (make-signed-request 1 "wrong-key")
          handler (wrap-authentication identity sbackend)
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Signed token unathorized request 1"
    (let [request (make-signed-request 1)
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization sbackend)
                      (wrap-authentication sbackend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Signed token unathorized request 2"
    (let [request (make-signed-request 1 "wrong-key")
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization sbackend)
                      (wrap-authentication sbackend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Signed token unathorized request 3"
    (let [request (make-signed-request 1 "wrong-key")
          onerror (fn [_ _] {:status 3000})
          backend (signed-token-backend {:privkey secret-key
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


