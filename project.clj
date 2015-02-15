(defproject buddy/buddy-auth "0.4.0-SNAPSHOT"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy-auth"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [buddy/buddy-core "0.4.0-SNAPSHOT"]
                 [buddy/buddy-sign "0.4.0-SNAPSHOT"]
                 [cuerdas "0.3.0"]
                 [slingshot "0.12.2"]
                 [ring/ring-core "1.3.2" :exclusions [org.clojure/tools.reader]]
                 [clout "2.1.0"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"]
  :profiles {:example {:dependencies [[compojure "1.3.1"]
                                      [ring "1.3.2"]]}
             :httpbasic-example
             [:example {:source-paths ["examples/httpbasic/src"]
                        :resource-paths ["examples/httpbasic/resources"]
                        :main ^:skip-aot httpbasic.core}]

             :session-example
             [:example {:source-paths ["examples/session/src"]
                        :resource-paths ["examples/session/resources"]
                        :main ^:skip-aot session.core}]})
