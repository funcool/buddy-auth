(ns buddy.auth.backends.httpbasic-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.codecs.base64 :as b64]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.http :as http]
            [buddy.auth.backends :as backends]
            [buddy.auth.backends.httpbasic :as httpbasic]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-header
  ([schema username password]
   (format "%s %s" schema (-> (b64/encode (format "%s:%s" username password))
                          (bytes->str)))))

(defn make-request
  ([] {:headers {}})
  ([username password]
   (make-request "Basic" username password))
  ([schema username password]
   (let [auth (make-header schema username password)]
     {:headers {"auThorIzation" auth "lala" "2"}})))

(defn auth-fn
  [request {:keys [username]}]
  (if (= username "foo")
    :valid
    :invalid))

(def backend
  (backends/http-basic
   {:authfn auth-fn :realm "Foo"}))

(deftest httpbasic-parse-test
  (testing "Parse httpbasic header from request"
    (let [parse #'httpbasic/parse-header
          request (make-request "foo" "bar")
          parsed  (parse request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar"))
      (is (= (:username parsed) "foo"))))
  (testing "Parse httpbasic header from request with colon in password"
    (let [parse #'httpbasic/parse-header
          request (make-request "foo" "bar:baz")
          parsed  (parse request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar:baz"))
      (is (= (:username parsed) "foo")))))
  (testing "Parsing httpbasic header as case insensitive schema"
    (let [parse #'httpbasic/parse-header
              request (make-request "BASIC" "Ufoo" "Ubar")
              parsed  (parse request)]
          (is (not (nil? parsed)))
          (is (= (:password parsed) "Ubar"))
          (is (= (:username parsed) "Ufoo")))
    (let [parse #'httpbasic/parse-header
                  request (make-request "basic" "lfoo" "lbar")
                  parsed  (parse request)]
              (is (not (nil? parsed)))
              (is (= (:password parsed) "lbar"))
              (is (= (:username parsed) "lfoo"))))

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
