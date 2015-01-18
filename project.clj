(defproject buddy/buddy-auth "0.3.0-SNAPSHOT"
  :description "Security library for Clojure"
  :url "https://github.com/niwibe/buddy"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [buddy/buddy-core "0.3.0"]
                 [buddy/buddy-sign "0.3.0"]
                 [slingshot "0.12.1"]
                 [ring/ring-core "1.3.2" :exclusions [org.clojure/tools.reader]]
                 [clout "2.1.0"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"]
  :profiles {:speclj {:dependencies [[speclj "3.1.0"]]
                      :test-paths ["spec"]
                      :plugins [[speclj "3.1.0"]]}
             :example {:dependencies [[compojure "1.3.1"]
                                      [ring "1.3.2"]]}
             :sessionexample [:example
                              {:source-paths ["examples/sessionexample/src"]
                               :resource-paths ["examples/sessionexample/resources"]
                               :target-path "examples/sessionexample/target/%s"
                               :main ^:skip-aot sessionexample.core}]
             :oauthexample [:example
                            {:dependencies [[clj-http "0.7.9"]
                                            [hiccup "1.0.5"]
                                            [org.clojure/data.json "0.2.4"]]
                             :source-paths ["examples/oauthexample/src"]
                             :resource-paths ["example/oauthexample/resources"]
                             :target-path "examples/oauthexample/target/%s"
                             :main ^:skip-aot oauthexample.core}]})
