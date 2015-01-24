(ns buddy.auth.backends.httpbasic-tests
  (:require [clojure.test :refer :all]
            [ring.util.response :refer [response? response]]
            [buddy.core.codecs :refer :all]
            [buddy.sign.generic :as s]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends.httpbasic :refer [http-basic-backend parse-httpbasic-header]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-header
  [username password]
  (format "Basic %s" (str->base64 (format "%s:%s" username password))))

(defn make-request
  ([] {:headers {}})
  ([username password]
   (let [auth (make-header username password)]
     {:headers {"Authorization" auth "lala" "2"}})))

(defn auth-fn
  [request {:keys [username]}]
  (if (= username "foo")
    :valid
    :invalid))

(deftest httpbasic-parse-test
  (testing "Parse httpbasic header from request"
    (let [request (make-request "foo" "bar")
          parsed  (parse-httpbasic-header request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar"))
      (is (= (:username parsed) "foo")))))

(def backend (http-basic-backend {:authfn auth-fn :realm "Foo"}))

(deftest httpbasic-auth-backend
  (testing "Testing anon request"
    (let [handler (wrap-authentication identity backend)
          request (make-request)
          response (handler request)]
      (is (= (:identity response) nil))))

  (testing "Test wrong request"
    (let [handler (wrap-authentication identity backend)
          request (make-request "test" "test")
          response (handler request)]
      (is (= (:identity response) :invalid))))

  (testing "Test auth request"
    (let [handler (wrap-authentication identity backend)
          request (make-request "foo" "bar")
          response (handler request)]
      (is (= (:identity response) :valid))))

  (testing "Authorization middleware tests 01"
    (let [handler (-> (fn [req] (if (nil? (:identity req))
                                  (throw-unauthorized {:msg "FooMsg"})
                                  req))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "user" "pass")
          response (handler request)]
      (is (= (:identity response) :invalid))))

  (testing "Authorization middleware tests 02 with httpbasic backend"
    (let [handler (-> (fn [req] (if (nil? (:identity req))
                                  (throw-unauthorized {:msg "FooMsg"})
                                  req))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "foo" "pass")
          response (handler request)]
      (is (= (:identity response) :valid))))

  (testing "Authorization middleware tests 03 with httpbasic backend"
    (let [handler (-> (fn [req] (throw-unauthorized {:msg "FooMsg"}))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "foo" "pass")
          response (handler request)]
      (is (= (:status response) 403)))))
