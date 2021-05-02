#!/bin/sh

mvn deploy:deploy-file -Dfile=target/buddy-auth.jar -DpomFile=pom.xml -DrepositoryId=clojars -Durl=https://clojars.org/repo/
