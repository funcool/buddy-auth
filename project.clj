(defproject buddy/buddy-auth "0.5.0-SNAPSHOT"
  :description "Authentication and Authorization facilities for ring based web applications."
  :url "https://github.com/funcool/buddy-auth"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [buddy/buddy-sign "0.5.0-SNAPSHOT"]
                 [cuerdas "0.3.2"]
                 [slingshot "0.12.2"]
                 [ring/ring-core "1.3.2" :exclusions [org.clojure/tools.reader]]
                 [clout "2.1.1"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])
