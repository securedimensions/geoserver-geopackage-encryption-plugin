#!/bin/bash
cd target && rm -f geoserver-geopackage-encryption-plugin-1.0-SNAPSHOT.zip && zip geoserver-geopackage-encryption-plugin-1.0-SNAPSHOT.zip geoserver-geopackage-encryption-plugin-1.0-SNAPSHOT.jar -j  dependency/nimbus-jose-jwt-9.7.jar dependency/bcpkix-jdk15on-1.69.jar dependency/bcutil-jdk15on-1.69.jar  dependency/gs-mbtiles-2.20-SNAPSHOT.jar dependency/gt-mbtiles-26-SNAPSHOT.jar
