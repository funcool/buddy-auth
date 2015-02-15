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

(def auth-backend
  (reify
    proto/IAuthentication
    (parse [_ request]
      (::authdata request))

    (authenticate [_ request data]
      (if (= data ::ok)
        (assoc request :identity :valid)
        (assoc request :identity :invalid)))))

(deftest wrap-authentication
  (testing "Using auth requests"
    (let [handler (mw/wrap-authentication identity auth-backend)
          response (handler {::authdata ::ok})]
      (is (= (:identity response) :valid))
      (is (= (::authdata response) ::ok))))

  (testing "Using anon request"
    (let [handler (mw/wrap-authentication identity auth-backend)
          response (handler {})]
      (is (= (:identity response) nil))
      (is (= (::authdata response) nil))))

  (testing "Using wrong request"
    (let [handler (mw/wrap-authentication identity auth-backend)
          response (handler {::authdata ::fake})]
      (is (= (:identity response) :invalid))
      (is (= (::authdata response) ::fake)))))

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
