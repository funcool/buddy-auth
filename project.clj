(defproject buddy/buddy-auth "0.6.0"
  :description "Authentication and Authorization facilities for ring based web applications."
  :url "https://github.com/funcool/buddy-auth"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.6.0" :scope "provided"]
                 [buddy/buddy-sign "0.6.0"]
                 [funcool/cuerdas "0.5.0"]
                 [clout "2.1.2"]]
  :source-paths ["src"]
  :test-paths ["test"]
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :profiles {:dev {:codeina {:sources ["src"]
                             :exclude []
                             :language :clojure
                             :output-dir "doc/dist/latest/api"
                             :src-dir-uri "http://github.com/funcool/buddy-auth/blob/master/"
                             :src-linenum-anchor-prefix "L"}
                   :plugins [[funcool/codeina "0.1.0"
                              :exclusions [org.clojure/clojure]]]}})
