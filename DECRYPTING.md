# Decrypting the Encrypted GeoPackage Format
The encrypted data for Features or Tiles is stored as a SQLite BLOB. Each BLOB starts with the Initialization Vecotr (16 Bytes) directly followed by the actually encrypted data.

In order to decrypt the data, you first need to fetch the (decryption) key from the [Key Management System](htts://ogc.secure-dimensions.com/kms). With the obtained key, the actual data can be decrypted.

In the following, you'll see a manual step-by-step walk through leveraging Linux command line tools:

* sqlite3
* cut 
* base64 
* sed 
* jq

Please make sure you have installed these tools.


## Extract the encrypted data and key metadata
Open the geopackage file with sqlite3:

* $> `sqlite3 <your geopackage file\>`

Extract the table names that store encrypted data

* sqlite> `SELECT table_name from gpkg_extensions WHERE extension_name='sd_encrypted_features' AND column_name IS NULL AND table_name!='gpkg_ext_keys';`

Extract the encrypted data into a file (from feature table name `poi`)

* sqlite> `SELECT writefile('feature.1.bin', data) FROM poi LIMIT 1;`

Extract the (decryption) key metadata for table `poi`

* sqlite> `.output dek.jws`
* sqlite> `SELECT gpkg_ext_keys.data FROM gpkg_ext_keys INNER JOIN poi ON gpkg_ext_keys.id=poi.key_id LIMIT 1;`
* sqlite> `.quit`

As a result, the file `feature.1.bin` contains the encrypted data for the first feature from the GeoPackage table `poi`. The file `dek.jws` contains the (decryption) key metadata as JWS. For example 

`eyJqa3UiOiJodHRwczpcL1wvb2djLnNlY3VyZS1kaW1lbnNpb25zLmNvbVwvZGNzXC8ud2VsbC1rbm93blwvandrcy5qc29uIiwia2lkIjoiRHIuIE5vIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI5NWQzODI3ZC1lZmVmLTMwNTItYTJkZi00NmQxYzdjZTc3YTUiLCJhdWQiOiIwMTliNzE3My1hOWVkLTdkOWEtNzBkMy05NTAyYWQ3YzA1NzUiLCJrdXJsIjoiaHR0cHM6XC9cL29nYy5zZWN1cmUtZGltZW5zaW9ucy5jb21cL2ttc1wvZGVrXC83NTJhNjExYy1kZjRhLTQxNDAtOTcxMS0xOWRhNWNhODVjYzkiLCJraWQiOiI3NTJhNjExYy1kZjRhLTQxNDAtOTcxMS0xOWRhNWNhODVjYzkiLCJpc3MiOiJodHRwczpcL1wvb2djLnNlY3VyZS1kaW1lbnNpb25zLmNvbSIsImV4cCI6MTYzMjQ4MywiYWxnIjoiQTEyOENCQ19IUzI1NiIsImlhdCI6MTYzMjQ4MjgwMH0.glNinXNNPFiWxzeZMnyFcFvwZLZucz1LCzaeUXIi6y7aUpU3wHTUOyggBRHLXFxloGkxH2QFoP-1MRvZ3ddVWmyNJDucboUSqMFwgG8Au7NCtYKRoU8I9rYpmVWgEaOPujUQMgVlcWUIm36s9BETdgwnDLe4TCLswuhTdO9hnss_SOBItN2Hgndn_TZjVxVJrptILOSxF0NDYi6V0KLSe7LUGfzyikTI9nlHpW-xjuNasU1-TxwywvOdkvqxF0shlCwlGYlCXjAlvGPFAufHITQqXtIhwrfHR9EPtS-kr2O79_-AI4E1NDT7vUEJxZYqyGsNwvI6UDBV-QZFV0rAgg`

## Extract the key identifier from the metadata
For this example, the signature validation is skipped.

The (decryption) key can be fetched from the KMS via the `kid` or the `kurl` included in the payload of the JWS. To extract the information, you can use [JWT.io](https://jwt.io) or the following Linux shell command

* $> `cut -d '.' -f 2 dek.jws | base64 -d | sed 's/\\//g' | sed -e 's/$/}/g' | jq -r '.kid'`

This echos the UUID of the key. E.g. `752a611c-df4a-4140-9711-19da5ca85cc9`

Alternatively, you can also fetch the `kurl` from the JWS with the following Linux shell command

* $> `cut -d '.' -f 2 dek.jws | base64 -d | sed 's/\\//g' | sed -e 's/$/}/g' | jq -r '.kurl'`

This echoes the URL to fetch the key. But please note that you need to add the HTTP Authorization header with method Bearer <access_token\>. E.g. `https://ogc.secure-dimensions.com/kms/dek/752a611c-df4a-4140-9711-19da5ca85cc9`

## Fetch the (decryption) key from the KMS
With the `kid` obtained in the previous step, you can use the [KMS OpenAPI](https://ogc.secure-dimensions.com/kms/developers#/DEK/getKeyById) to fetch the key and downloa it into file `dek.json`.

The key is in JWK format:

```json
{
  "kid": "752a611c-df4a-4140-9711-19da5ca85cc9",
  "alg": "A128CBC_HS256",
  "kty": "oct",
  "k": "qhDKbmX3TIVNy-7jlLTc8A",
  "issuer": "4bf1cb21-9ff7-f443-f736-70781d89d413",
  "expires": 1632483100,
  "issued_at": 1632482802,
  "aud": "019b7173-a9ed-7d9a-70d3-9502ad7c0575",
  "sub": "95d3827d-efef-3052-a2df-46d1c7ce77a5"
}
```

## Decrypt the data
Depending on your favorite platform, different options exist how to decrypt the data. 

One tested option is based on the [Nimbus JOSE library](https://connect2id.com/products/nimbus-jose-jwt/examples/jwe-with-shared-key) example for direct en/decryption.

