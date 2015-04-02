(ns buddy.auth.backends.token-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response?]]
            [buddy.core.codecs :refer :all]
            [buddy.sign.jws :as jws]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends.token :as token]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(def secret "test-secret-key")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-request
  [token]
  (let [header (format "Token %s" token)]
    {:headers {"auThorIzation" header}}))

(defn make-jws-request
  [data secret]
  (let [header (->> (jws/sign {:userid 1} secret)
                    (format "Token %s"))]
    {:headers {"authorization" header}}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: parse
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest token-parse-test
  (testing "Parse authorization header"
    (let [request (make-request "foo")
          parsed  (token/parse-authorization-header request "Token")]
      (is (= parsed "foo"))))

  (testing "Parse authorization header different header name yields nil"
    (let [parsed (token/parse-authorization-header (make-request "foo") "MyToken")]
     (is (= parsed nil)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: JWS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def jws-secret "mysuperjwssecret")
(def jws-backend (token/jws-backend {:secret jws-secret}))
(def jws-data {:userid 1})

(deftest jws-backend-test
  (testing "Jws token backend authentication"
    (let [request (make-jws-request jws-data jws-secret)
          handler (wrap-authentication identity jws-backend)
          response (handler request)]
      (is (= (:identity response) jws-data))))

  (testing "Jws token backend authentication with wrong key yields nil"
    (let [request (make-jws-request jws-data  "wrong-key")
          handler (wrap-authentication identity jws-backend)
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Jws token backend authentication with no token yields nil"
    (let [request {}
          handler (wrap-authentication identity jws-backend)
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Jws token authorizaton with wrong key yields 401"
    (let [request (make-jws-request jws-data "wrong-key")
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jws-backend)
                      (wrap-authentication jws-backend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Jws token authorization - authenticated but unathorized thrown yields 403"
    (let [request (make-jws-request {:userid 1} jws-secret)
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jws-backend)
                      (wrap-authentication jws-backend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Jws token unathorized - unauth handler called when provided"
    (let [request (make-jws-request jws-data "wrong-key")
          onerror (fn [_ _] {:status 3000})
          backend (token/jws-backend {:secret jws-secret
                                      :unauthorized-handler onerror})
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: Token
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn token-authfn
  [request token]
  (let [data {:token1 {:userid 1}
              :token2 {:userid 2}}]
    (get data (keyword token))))

(def backend (token/token-backend {:authfn token-authfn}))

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
          backend (token/token-backend {:authfn token-authfn
                                        :unauthorized-handler onerror})
          handler (-> (fn [request] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
        (is (= (:status response) 3000)))))
