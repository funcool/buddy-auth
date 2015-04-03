#!/bin/sh
VERSION="latest"

lein doc
(cd doc; make)

rm -rf /tmp/buddy-doc/
mkdir -p /tmp/buddy-doc/
mv doc/index.html /tmp/buddy-doc/
mv doc/api /tmp/buddy-doc/api

git checkout gh-pages;

rm -rf ./$VERSION
mv /tmp/buddy-doc/ ./$VERSION

git add --all ./$VERSION
git commit -a -m "Update ${VERSION} doc"
