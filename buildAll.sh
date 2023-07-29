#!/bin/bash
# Builds all services and prepares for deploy

root="$PWD"
cd "$root"

cd "$root"/tms-qms
mvn clean install -DskipTests

cd "$root"/tms-cms
mvn clean install -DskipTests

cd "$root"/tms-ems
mvn clean install -DskipTests

cd "$root"/tms-ums
mvn clean install -DskipTests

