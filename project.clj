(defproject buddy/buddy-auth "3.0.0"
  :description "Authentication and Authorization facilities for ring based web applications."
  :url "https://github.com/funcool/buddy-auth"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.10.3" :scope "provided"]
                 [buddy/buddy-sign "3.4.0"]
                 [clout "2.2.1"]]

  :jar-name "buddy-auth.jar"
  :source-paths ["src"]
  :test-paths ["test"]
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.8" "-source" "1.8" "-Xlint:-options"])
