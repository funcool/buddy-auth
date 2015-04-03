(defproject authexample "0.1.0-SNAPSHOT"
  :description "Buddy auth example"
  :min-lein-version "2.0.0"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [compojure "1.3.2"]
                 [ring "1.3.2"]
                 [ring/ring-jetty-adapter "1.3.2"]
                 [buddy/buddy-auth "0.5.0"]]
  :ring {:handler authexample.web/app
         :port 9090}
  :profiles {:dev {:plugins [[lein-ring "0.9.3"]]
                   :test-paths ^:replace []}})
