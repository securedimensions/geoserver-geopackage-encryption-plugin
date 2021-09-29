# Geoserver Geopackage Encryption Extension

This plugin allows to fetch GeoPackage with encrypted data. The GeoPackage Encryption Extension is documented in the OGC Public Engineering Report from the OGC Disaster Pilot '21 project. The URL for this report will be [https://docs.ogc.org/per/21-064.html](https://docs.ogc.org/per/21-064.html) once published (expected for early 2022).

In a nutshell, the GeoPackage Encryption Extension comprises of an extra table named `gpkg_ext_keys` that contains the metadata of the encrpytion key encoded a JWS (JSON Web Signature). This allows to verify the integrity of the key metadata with the public key of the issuer (the entity that operates the GeoServer including this plugin).

This plugin extends the use of the GeoServer's OGC Web Map Service version 1.1.0 and Web Feature Service 2.0.0 with the media type `application/geopackage-sqlite3;profile=encrypted`. 

In order to request a GeoPackage output format with encrypted data, the requesting application must submit additional parameters that are not part of the WMS and WFS specifications:

* `access_token` = <your access token\>
* `key_challenge` = <a secret pin or password to modify key usage\>
* `key_challenge_method` = plain
* For WFS `outputFormat` = application/geopackage-sqlite3;profile=encrypted
* For WMS `format` = application/geopackage-sqlite3;profile=encrypted

The GeoPackage including encrypted tiles can be requested via the WMS 1.1.0 interface. One GeoPackage table is created with the rendered map from all the layer names provided with the request. All tiles with different zoom levels get packaged into this table. 

The GeoPackage including encrypted features can be requested via WFS 2.0.0 interface. One GeoPackage table is created per feature type requested with the `typeName` parameter. Each feature type is encrypted with a different key. The link to the key's metadata is done via a foreign key into the `gpkg_ext_keys` table.

* [Installing the GeoPackage Encryption plugin](/INSTALL.md)
* [Decrypting the Encrypted GeoPackage Format](/DECRYPTING.md)
