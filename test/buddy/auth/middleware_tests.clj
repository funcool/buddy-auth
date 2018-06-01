(ns buddy.auth.middleware-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.protocols :as proto]
            [buddy.auth.middleware :as mw]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication middleware testing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn auth-backend
  [secret token-name]
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (get request token-name))

    (-authenticate [_ request data]
      (assert data)
      (when (= data secret)
        :valid))))

(defn- async-identity [req respond _]
  (respond req))

(deftest wrap-authentication
  (testing "Using auth requests"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok ::authdata))
          response (handler {::authdata ::ok})]
      (is (= (:identity response) :valid))
      (is (= (::authdata response) ::ok))))

  (testing "Using auth async requests"
    (let [handler (-> async-identity
                      (mw/wrap-authentication (auth-backend ::ok ::authdata)))
          response (promise)
          exception (promise)]
      (handler {::authdata ::ok} response exception)
      (is (= (:identity @response) :valid))
      (is (= (::authdata @response) ::ok))
      (is (not (realized? exception)))))

  (testing "Using anon request"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok ::authdata))
          response (handler {})]
      (is (= (:identity response) nil))
      (is (= (::authdata response) nil))))

  (testing "Using anon async request"
    (let [handler (-> async-identity
                      (mw/wrap-authentication (auth-backend ::ok ::authdata)))
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= (:identity @response) nil))
      (is (= (::authdata @response) nil))
      (is (not (realized? exception)))))

  (testing "Using wrong request"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok ::authdata))
          response (handler {::authdata ::fake})]
      (is (nil? (:identity response)))
      (is (= (::authdata response) ::fake))))

  (testing "Using wrong async request"
    (let [handler (-> async-identity
                      (mw/wrap-authentication (auth-backend ::ok ::authdata)))
          response (promise)
          exception (promise)]
      (handler {::authdata ::fake} response promise)
      (is (nil? (:identity @response)))
      (is (= (::authdata @response) ::fake))
      (is (not (realized? exception))))))

(deftest wrap-authentication-with-multiple-backends
  (let [backends [(auth-backend ::ok-1 ::authdata)
                  (auth-backend ::ok-2 ::authdata2)]
        handler (apply mw/wrap-authentication identity backends)
        async-handler (apply mw/wrap-authentication async-identity backends)]

    (testing "backend #1 succeeds"
      (let [response (handler {::authdata ::ok-1})]
        (is (= (:identity response) :valid))
        (is (= (::authdata response) ::ok-1))))

    (testing "backend #1 succeeds for async"
      (let [response (promise)
            exception (promise)]
        (async-handler {::authdata ::ok-1} response exception)
        (is (= (:identity @response) :valid))
        (is (= (::authdata @response) ::ok-1))
        (is (not (realized? exception)))))

    (testing "backend #2 succeeds"
      (let [response (handler {::authdata2 ::ok-2})]
        (is (= (:identity response) :valid))
        (is (= (::authdata2 response) ::ok-2))))

    (testing "backend #2 succeeds for async"
      (let [response (promise)
            exception (promise)]
        (async-handler {::authdata2 ::ok-2} response exception)
        (is (= (:identity @response) :valid))
        (is (= (::authdata2 @response) ::ok-2))
        (is (not (realized? exception)))))

    (testing "no backends succeeds"
      (let [response (handler {::authdata ::fake})]
        (is (nil? (:identity response)))
        (is (= (::authdata response) ::fake))))

    (testing "no backends succeeds for async"
      (let [response (promise)
            exception (promise)]
        (async-handler {::authdata ::fake} response exception)
        (is (nil? (:identity @response)))
        (is (= (::authdata @response) ::fake))
        (is (not (realized? exception)))))

    (testing "handler called exactly once"
      (let [state (atom 0)
            counter (fn [request] (swap! state inc) request)
            handler (apply mw/wrap-authentication counter backends)
            response (handler {::authdata ::fake})]
        (is (nil? (:identity response)))
        (is (= (::authdata response) ::fake))
        (is (= @state 1))))

    (testing "async handler called exactly once"
      (let [state (atom 0)
            counter (fn [request respond raise]
                      (swap! state inc)
                      (respond request))
            handler (apply mw/wrap-authentication counter backends)
            response (promise)
            exception (promise)]
        (handler {::authdata ::fake} response exception)
        (is (nil? (:identity @response)))
        (is (= (::authdata @response) ::fake))
        (is (= @state 1))
        (is (not (realized? exception)))))

    (testing "with zero backends"
      (let [request {:uri "/"}]
        (is (= ((mw/wrap-authentication identity) request) request))))

    (testing "with zero backends for async"
      (let [request {:uri "/"}
            response (promise)
            exception (promise)]
        ((mw/wrap-authentication async-identity) request response exception)
        (is (= @response request))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authorization middleware testing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def autz-backend
  (reify
    proto/IAuthorization
    (-handle-unauthorized [_ request data]
      {:body "error" :status 401 :data data})))

(deftest wrap-authorization
  (testing "Simple authorized request"
    (let [handler (mw/wrap-authorization identity autz-backend)
          response (handler {:foo :bar})]
      (is (= (:foo response) :bar))))

  (testing "Simple authorized async request"
    (let [handler (mw/wrap-authorization async-identity autz-backend)
          response (promise)
          exception (promise)]
      (handler {:foo :bar} response exception)
      (is (= (:foo @response) :bar))
      (is (not (realized? exception)))))

  (testing "Unauthorized request"
    (let [handler (fn [req]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler autz-backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar}))))

  (testing "Unauthorized async request"
    (let [handler (fn [req respond raise]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler autz-backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= (:body @response) "error"))
      (is (= (:status @response) 401))
      (is (= (:data @response) {:foo :bar}))
      (is (not (realized? exception)))))

  ;; (testing "Unauthorized request with custom exception"
  ;;   (let [handler (fn [req]
  ;;                   (throw (proxy [Exception proto/IAuthorization] []
  ;;                            proto/IAuthorizationdError
  ;;                            (-get-error-data [_]
  ;;                              {:foo :bar}))))
  ;;         handler (mw/wrap-authorization handler autz-backend)
  ;;         response (handler {})]
  ;;     (is (= (:body response) "error"))
  ;;     (is (= (:status response) 401))
  ;;     (is (= (:data response) {:foo :bar}))))

  (testing "Unauthorized request with backend as function"
    (let [backend (fn [request data] {:body "error" :status 401 :data data})
          handler (fn [req]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar}))))

  (testing "Unauthorized async request with backend as function"
    (let [backend (fn [request data] {:body "error" :status 401 :data data})
          handler (fn [req respond raise]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= (:body @response) "error"))
      (is (= (:status @response) 401))
      (is (= (:data @response) {:foo :bar}))
      (is (not (realized? exception))))))
