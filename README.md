# Geoserver Geopackage Encryption Extension

This GeoServer module allows to create a Secure GeoPackage with encrypted data compliant with the GeoPackage Encryption Extension as documented in the OGC Public Engineering Report from the OGC Disaster Pilot '21 project. The URL for this report will be [https://docs.ogc.org/per/21-064.html](https://docs.ogc.org/per/21-064.html) once published (expected for early 2022).

In a nutshell, the GeoPackage Encryption Extension comprises of an extra table named `gpkg_ext_keys` that contains the metadata of the encrpytion key encoded as a JWS (JSON Web Signature). This allows to verify the integrity of the key metadata with the public key of the issuer (the entity that operates the service which creates the Secure GeoPackage).

This GeoServer module extends the use of the OGC Web Map Service version 1.1.0 and Web Feature Service 2.0.0 with the media type `application/geopackage-sqlite3;profile=encrypted`. 

In order to request a Secure GeoPackage output format with encrypted data, the requesting application must submit additional parameters that are not part of the WMS and WFS specifications:

* `access_token` = <your access token\>
* `key_challenge` = <a secret pin or password to modify key usage\>
* `key_challenge_method` = plain
* `key_id`= <the key identifier of an encryption key registered with the Key Management System>
* For WFS `outputFormat` = application/geopackage+sqlite3;profile=encrypted
* For WMS `format` = application/geopackage+sqlite3;profile=encrypted

The GeoPackage including encrypted tiles can be requested via the WMS 1.1.0 interface. One GeoPackage table is created with the rendered map from all the layer names provided with the request. All tiles with different zoom levels get packaged into this table. 

The GeoPackage including encrypted features can be requested via WFS 2.0.0 interface. One GeoPackage table is created per feature type requested with the `typeNames` parameter. 

Each feature type / tile layer is encrypted with a different key unless the `key_id` parameter is used. The link to the key's metadata is done from the content table into the `gpkg_ext_keys` table via the foreign key `kid`.

This GeoServer module cannot be operated without other required components as described in the OGC Public Engineering Report from the OGC Disaster Pilot '21 project [https://docs.ogc.org/per/21-064.html](https://docs.ogc.org/per/21-064.html)

* [Installing the GeoPackage Encryption plugin](/INSTALL.md)
* [Understand how to decrypt the Secure GeoPackage Format](/DECRYPTING.md)
* [Decryption demonstration using QGIS](/DEMO.md)
