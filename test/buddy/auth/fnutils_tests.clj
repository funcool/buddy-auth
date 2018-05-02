(ns buddy.auth.fnutils-tests
  (:require [clojure.test :refer :all]           
            [buddy.auth.fnutils :refer [fn->multi]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Arity macro testing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(deftest arity-dispatching
  (testing "Calling arity-1"
    (let [handler (fn->multi [request] request)]
      (is (= :ok (handler :ok)))))

  (testing "Calling arity-3"
    (let [handler (fn->multi [request] request)]
      (is (= :ok (handler :ok identity identity)))))

  (testing "Calling arity-3 with exception"
    (let [handler (fn->multi [request] (throw (Exception. "error")))]
      (is (thrown? Exception 
                   (handler :ok identity #(throw %)))))))
