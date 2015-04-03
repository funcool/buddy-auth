(ns buddy.auth.backends.token-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response?]]
            [buddy.core.codecs :refer :all]
            [buddy.core.hash :as hash]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwe :as jwe]
            [buddy.auth :refer [throw-unauthorized authenticated?]]
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: parse
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest token-parse-test
  (testing "Parse authorization header"
    (let [request (make-request "foo")
          parse #'token/parse-authorization-header
          parsed  (parse request "Token")]
      (is (= parsed "foo"))))

  (testing "Parse authorization header different header name yields nil"
    (let [parse #'token/parse-authorization-header
          parsed (parse (make-request "foo") "MyToken")]
     (is (= parsed nil)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: JWS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def jws-secret "mysuperjwssecret")
(def jws-backend (token/jws-backend {:secret jws-secret}))
(def jws-data {:userid 1})

(defn make-jws-request
  [data secret]
  (let [header (->> (jws/sign data secret)
                    (format "Token %s"))]
    {:headers {"authorization" header}}))

(deftest jws-backend-test
  (testing "Jws token backend authentication"
    (let [request (make-jws-request jws-data jws-secret)
          handler (wrap-authentication identity jws-backend)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') jws-data))))

  (testing "Jws token backend authentication with wrong key yields nil"
    (let [request (make-jws-request jws-data  "wrong-key")
          handler (wrap-authentication identity jws-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Jws token backend authentication without token yields nil"
    (let [request {}
          handler (wrap-authentication identity jws-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Jws token authorizaton with wrong key yields 401"
    (let [request (make-jws-request jws-data "wrong-key")
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jws-backend)
                      (wrap-authentication jws-backend))
          response (handler request)]
      (is (= (:status response) 401))
      (is (= (:body response) "Unauthorized"))))

  (testing "Jws token authorization - authenticated but unathorized thrown yields 403"
    (let [request (make-jws-request {:userid 1} jws-secret)
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jws-backend)
                      (wrap-authentication jws-backend))
          response (handler request)]
      (is (= (:status response) 403))
      (is (= (:body response) "Permission denied"))))

  (testing "Jws token unathorized - :unauthorized-handlercalled when provided"
    (let [request (make-jws-request jws-data "wrong-key")
          onerror (fn [_ _] {:status 3000})
          backend (token/jws-backend {:secret jws-secret
                                      :unauthorized-handler onerror})
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000))))

  (testing "Jws token wrongdata - onerror handler called when provided"
    (let [request (make-jws-request jws-data "wrong-key")
          onerror (fn [_ _] {:status 3000})
          backend (token/jws-backend {:secret jws-secret
                                      :on-error onerror})
          handler (-> identity
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000)))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: JWE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def jwe-secret (hash/sha256 "mysupersecretkey"))
(def jwe-backend (token/jwe-backend {:secret jwe-secret}))
(def jwe-data {:userid 1})

(defn make-jwe-request
  [data secret]
  (let [header (->> (jwe/encrypt data secret)
                    (format "Token %s"))]
    {:headers {"authorization" header}}))

(deftest jwe-backend-test
  (testing "Jwe token backend authentication"
    (let [request (make-jwe-request jwe-data jwe-secret)
          handler (wrap-authentication identity jwe-backend)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') jwe-data))))

  (testing "Jwe token backend authentication with wrong key yields nil"
    (let [request (make-jwe-request jwe-data (hash/sha256 "wrong-key"))
          handler (wrap-authentication identity jwe-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Jwe token backend authentication with no token yields nil"
    (let [request {}
          handler (wrap-authentication identity jwe-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Jwe token authorizaton with wrong key yields 401"
    (let [request (make-jwe-request jwe-data (hash/sha256 "wrong-key"))
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jwe-backend)
                      (wrap-authentication jwe-backend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Jwe token authorization - authenticated but unathorized thrown yields 403"
    (let [request (make-jwe-request {:userid 1} jwe-secret)
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization jwe-backend)
                      (wrap-authentication jwe-backend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Jwe token unathorized - unauth handler called when provided"
    (let [request (make-jwe-request jwe-data (hash/sha256 "wrong-key"))
          onerror (fn [_ _] {:status 3000})
          backend (token/jwe-backend {:secret jwe-secret
                                      :unauthorized-handler onerror})
          handler (-> (fn [req] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000))))

  (testing "Jwe token wrongdata - onerror handler called when provided"
    (let [request (make-jwe-request jws-data (hash/sha256 "foobar"))
          onerror (fn [_ _] {:status 3000})
          backend (token/jwe-backend {:secret jwe-secret
                                      :on-error onerror})
          handler (-> identity
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
