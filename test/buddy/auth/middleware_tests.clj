(ns buddy.auth.middleware-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [slingshot.slingshot :refer [throw+ try+]]
            [buddy.core.codecs :refer :all]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.protocols :as proto]
            [buddy.auth.middleware :as mw]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication middleware testing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn auth-backend [secret]
  (reify
    proto/IAuthentication
    (parse [_ request]
      (::authdata request))

    (authenticate [_ request data]
      (if (= data secret)
        (assoc request :identity :valid)))))

(deftest wrap-authentication
  (testing "Using auth requests"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok))
          response (handler {::authdata ::ok})]
      (is (= (:identity response) :valid))
      (is (= (::authdata response) ::ok))))

  (testing "Using anon request"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok))
          response (handler {})]
      (is (= (:identity response) nil))
      (is (= (::authdata response) nil))))

  (testing "Using wrong request"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok))
          response (handler {::authdata ::fake})]
      (is (nil? (:identity response)))
      (is (= (::authdata response) ::fake)))))

(deftest wrap-authentication-with-multiple-backends
  (let [backends [(auth-backend ::ok-1) (auth-backend ::ok-2)]
        handler (apply mw/wrap-authentication identity backends)]

    (testing "backend #1 succeeds"
      (let [response (handler {::authdata ::ok-1})]
        (is (= (:identity response) :valid))
        (is (= (::authdata response) ::ok-1))))

    (testing "backend #2 succeeds"
      (let [response (handler {::authdata ::ok-2})]
        (is (= (:identity response) :valid))
        (is (= (::authdata response) ::ok-2))))

    (testing "no backends succeeds"
      (let [response (handler {::authdata ::fake})]
        (is (nil? (:identity response)))
        (is (= (::authdata response) ::fake))))

    (testing "handler called exactly once"
      (let [state (atom 0)
            counter (fn [request] (swap! state inc) request)
            handler (apply mw/wrap-authentication counter backends)
            response (handler {::authdata ::fake})]
        (is (nil? (:identity response)))
        (is (= (::authdata response) ::fake))
        (is (= @state 1))))

    (testing "with zero backends"
      (let [request {:uri "/"}]
        (is (= ((mw/wrap-authentication identity) request) request))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authorization middleware testing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def autz-backend
  (reify
    proto/IAuthorization
    (handle-unauthorized [_ request data]
      {:body "error" :status 401 :data data})))

(deftest wrap-authorization
  (testing "Simple authorized request"
    (let [handler (mw/wrap-authorization identity autz-backend)
          response (handler {:foo :bar})]
      (= (:ok response) :bar)))

  (testing "Unauthorized request"
    (let [handler (fn [req]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler autz-backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar}))))

  (testing "Unauthorized request with custom exception"
    (let [handler (fn [req]
                    (throw+ (reify
                              proto/IAuthorizationdError
                              (get-error-data [_]
                                {:foo :bar}))))
          handler (mw/wrap-authorization handler autz-backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar}))))

  (testing "Unauthorized request with backend as function"
    (let [backend (fn [request data] {:body "error" :status 401 :data data})
          handler (fn [req]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar})))))
