{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.7:dev,1.8:dev,1.9:dev" "test"]}
  :codox {:project {:name "buddy-auth"}
          :metadata {:doc/format :markdown}
          :output-path "doc/dist/latest/"
          :doc-paths ["doc/"]
          :themes [:rdash]
          :source-paths ["src"]
          :source-uri "https://github.com/funcool/buddy-auth/blob/master/{filepath}#L{line}"
          :namespaces [#"^buddy\."]}
  :plugins [[lein-codox "0.10.7"]
            [lein-ancient "0.7.0"]]

  :dependencies [[codox-theme-rdash "0.1.2"]]}


 :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}
 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}

 :examples
 {:dependencies [[ring "1.6.2"]
                 [ring/ring-json "0.4.0"]
                 [compojure "1.6.0"]]}

 :session-example
 [:examples
  {:source-paths ["examples/session/src"]
   :resource-paths ["examples/session/resources"]
   :main ^:skip-aot authexample.web}]

 :httpbasic-example
 [:examples
  {:source-paths ["examples/httpbasic/src"]
   :resource-paths ["examples/httpbasic/resources"]
   :main ^:skip-aot authexample.web}]

 :token-example
 [:examples
  {:source-paths ["examples/token/src"]
   :resource-paths ["examples/token/resources"]
   :main ^:skip-aot authexample.web}]

 :jws-example
 [:examples
  {:source-paths ["examples/jws/src"]
   :resource-paths ["examples/jws/resources"]
   :main ^:skip-aot authexample.web}]

 :jwe-example
 [:examples
  {:source-paths ["examples/jwe/src"]
   :resource-paths ["examples/jwe/resources"]
   :main ^:skip-aot authexample.web}]
 }

