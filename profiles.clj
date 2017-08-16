{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.7:dev,1.8:dev" "test"]}
  :codeina {:sources ["src"]
            :reader :clojure
            :target "doc/dist/latest/api"
            :src-uri "http://github.com/funcool/buddy-auth/blob/master/"
            :src-uri-prefix "#L"}
  :plugins [[funcool/codeina "0.5.0"]
            [lein-ancient "0.6.10"]]}

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

