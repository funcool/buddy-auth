(require '[codox.main :as codox])

(codox/generate-docs
 {:output-path "doc/dist/latest"
  :metadata {:doc/format :markdown}
  :language :clojure
  :name "buddy/buddy-auth"
  :themes [:rdash]
  :source-paths ["src"]
  :namespaces [#"^buddy\."]
  :source-uri "https://github.com/funcool/buddy-auth/blob/master/{filepath}#L{line}"})
