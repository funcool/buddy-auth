(defproject authexample "0.1.0-SNAPSHOT"
  :description "Buddy auth example"
  :url ""
  :min-lein-version "2.0.0"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [compojure "1.2.1"]
                 [ring "1.3.1"]
                 [ring/ring-jetty-adapter "1.3.1"]
                 [ring/ring-json "0.3.1"]
                 [ring/ring-headers "0.1.1"]
                 [hiccup "1.0.5"]
                 [buddy/buddy-sign "0.4.0"]
                 [buddy/buddy-auth "0.4.0"]]
  :ring {:handler authexample.web/app
         :port 9090}
  :profiles {:dev {:plugins [[lein-ring "0.8.13"]]
                   :test-paths ^:replace []}
             :test {:dependencies [[midje "1.6.3"]]
                    :plugins [[lein-midje "3.1.3"]]
                    :test-paths ["test"]
                    :resource-paths ["test/resources"]}})
