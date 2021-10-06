# Installing Geoserver Geopackage Encryption Extension

This plugin is successfully compiled and deployed with [GeoServer v2.20](https://build.geoserver.org/geoserver/2.20.x/).

To install this plugin, you need to adopt the configuration of the plugin and create the JAR by cloning this repository.

## Adopting configuration
There are different configuration files that need to be created. All configuration examples use the [AUTHENIX](https://www.authenix.eu) Authorization Server.

### Create `src/main/resources/META-INF/TokenCache.properties`
Once the plugin is [registered with AUTHENIX]https://www.authenix.eu/registerapps as `Service Application`, you receive the `client_id` and `client_secret`. 

1. client_id=<the UUID resulting from registration\>
2. client_secret=<the secret for your application resulting from registration\>
3. token_info_endpoint=https://www.authenix.eu/oauth/tokeninfo

### Create `src/main/resources/META-INF/KmsProxy.properties`
You should not change this unless you have an alternative Key Management System in place.

1. dek_registration_endpoint=https://ogc.secure-dimensions.com/kms/dek

### Create `src/main/resources/META-INFO/GeoPackageGetFeatureOutputFormat.properties`
You need to adopt these settings to refelct you are the issuer! The `enc` value can be adopted to a supported AES algorithm (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM)

1. issuer=<the domain of the service\>
2. jwk_url=<the domain of the service\>/.well-known/jwks.json
3. pem_file_name=<the file that keeps the issuer's private key in PEM format\> (please put this file into directory `src/main/resources/`)
4. pem_kid=<the identifier from the JWKS.json file\>
5. dek_url=https://ogc.secure-dimensions.com/kms/dek/
6. enc=A128CBC-HS256

### Create `src/main/resources/META-INFO/GeoPackageGetMapOutputFormat.properties`
You need to adopt these settings to refelct you are the issuer! The `enc` value can be adopted to a supported AES algorithm (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM)

1. issuer=<the domain of the service\>
2. jwk_url=<the domain of the service\>/.well-known/jwks.json
3. pem_file_name=<the file that keeps the issuer's private key in PEM format\> (please put this file into directory `src/main/resources/`)
4. pem_kid=<the identifier from the JWKS.json file\>
5. dek_url=https://ogc.secure-dimensions.com/kms/dek/
6. enc=A128CBC-HS256



## Building the plugin

1. $> `git clone https://github.com/securedimensions/geoserver-geopackage-encryption-plugin.git` 
2. $> `cd geoserver-geopackage-encryption-plugin`
3. $> `mvn clean install -DskipTests dependency:copy-dependencies`
4. $> `./createZIP.sh`

## Installing the plugin
Extract the contents of the archive `target/geoserver-geopackage-encryption-plugin-1.0.SNAPSHOT.zip` into the `WEB-INF/lib` directory of your GeoServer deployment.

Once you have restarted the GeoServer, you can see the `Encrypted Geopackage` output format available for WFS and WMS with the `Layer Preview`.
