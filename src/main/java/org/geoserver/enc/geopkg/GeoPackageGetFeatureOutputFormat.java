/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.enc.geopkg;

import static java.lang.String.format;
import static org.geoserver.enc.geopkg.EncryptedGeoPackage.EXTENSION;
import static org.geoserver.enc.geopkg.EncryptedGeoPackage.MIME_TYPE;
import static org.geoserver.enc.geopkg.EncryptedGeoPackage.NAME;
import static org.geotools.jdbc.util.SqlUtil.prepare;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.config.GeoServer;
import org.geoserver.data.util.TemporalUtils;
import org.geoserver.enc.KmsProxy;
import org.geoserver.enc.TokenCache;
import org.geoserver.ows.Dispatcher;
import org.geoserver.ows.Request;
import org.geoserver.platform.Operation;
import org.geoserver.platform.ServiceException;
import org.geoserver.wfs.WFSGetFeatureOutputFormat;
import org.geoserver.wfs.json.GeoJSONBuilder;
import org.geoserver.wfs.request.FeatureCollectionResponse;
import org.geoserver.wfs.request.GetFeatureRequest;
import org.geotools.data.simple.SimpleFeatureCollection;
import org.geotools.data.simple.SimpleFeatureIterator;
import org.geotools.feature.FeatureCollection;
import org.geotools.geometry.jts.Geometries;
import org.geotools.geometry.jts.ReferencedEnvelope;
import org.geotools.geopkg.FeatureEntry;
import org.geotools.geopkg.GeoPackage;
import org.geotools.referencing.CRS;
import org.geotools.util.logging.Logging;
import org.locationtech.jts.geom.Coordinate;
import org.locationtech.jts.geom.CoordinateFilter;
import org.locationtech.jts.geom.CoordinateSequence;
import org.locationtech.jts.geom.CoordinateSequenceFilter;
import org.locationtech.jts.geom.Geometry;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.io.WKBWriter;
import org.locationtech.jts.io.WKTReader;
import org.opengis.feature.simple.SimpleFeature;
import org.opengis.feature.simple.SimpleFeatureType;
import org.opengis.feature.type.AttributeDescriptor;
import org.opengis.feature.type.FeatureType;
import org.opengis.feature.type.GeometryDescriptor;
import org.opengis.feature.type.GeometryType;
import org.opengis.referencing.crs.CoordinateReferenceSystem;
import org.opengis.referencing.cs.AxisDirection;
import org.opengis.referencing.cs.CoordinateSystem;

import com.google.common.collect.Lists;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.SecretJWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * WFS GetFeature OutputFormat for Encrypted GeoPackage
 *
 * @author Andreas Matheus, Secure Dimensions GmbH
 */
public class GeoPackageGetFeatureOutputFormat extends WFSGetFeatureOutputFormat {

	static Logger LOGGER = Logging.getLogger("org.geoserver.geopkg-encrypted");

	public static final String PROPERTY_INDEXED = "geopackage.wfs.indexed";

	private KeyGenerator keyGen = null;
	private SecretKey dek = null;
	private SignedJWT dekJWT = null;
	private JWSSigner signer = null;
	private JWSHeader jwsHeader = null;
	private Cipher cipher = null;
	private TokenCache tokenCache = null;

	private String issuer = null;
	private String jwkUrl = null;
	private String pemFileName = null;
	private String pemKid = null;
	private String dekUrl = null;
	private String enc = null;

	public GeoPackageGetFeatureOutputFormat(GeoServer gs) {
		super(gs, MIME_TYPE);

		try {
			InputStream stream = getClass().getClassLoader()
					.getResourceAsStream("META-INF/GeoPackageGetFeatureOutputFormat.properties");

			if (stream == null)
				throw new ServiceException("GeoPackageGetFeatureOutputFormat.properties files not found");

			Properties properties = new Properties();
			properties.load(stream);
			stream.close();

			issuer = (String) properties.get("issuer");
			if (issuer == null)
				throw new ServiceException("GeoPackageGetFeatureOutputFormat.properties missing parameter 'issuer'");

			jwkUrl = (String) properties.get("jwk_url");
			if (jwkUrl == null)
				throw new ServiceException("GeoPackageGetFeatureOutputFormat.properties missing parameter 'jwk_url'");

			pemFileName = (String) properties.get("pem_file_name");
			if (pemFileName == null)
				throw new ServiceException(
						"GeoPackageGetFeatureOutputFormat.properties missing parameter 'pem_file_name'");

			pemKid = (String) properties.get("pem_kid");
			if (pemKid == null)
				throw new ServiceException("GeoPackageGetFeatureOutputFormat.properties missing parameter 'pem_kid'");

			dekUrl = (String) properties.get("dek_url");
			if (dekUrl == null)
				throw new ServiceException("GeoPackageGetFeatureOutputFormat.properties missing parameter 'dek_url'");

			enc = (String) properties.get("enc");
			if (enc == null)
				throw new ServiceException("GeoPackageGetFeatureOutputFormat.properties missing parameter 'enc'");

			// generate a symmetric key
			int keySize = 128;

			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(keySize);

			InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(pemFileName);
			String pem = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
			RSAKey senderJWK = JWK.parseFromPEMEncodedObjects(pem).toRSAKey();
			jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(pemKid).jwkURL(new URI(jwkUrl)).build();

			signer = new RSASSASigner(senderJWK);

			// For AES key
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			tokenCache = new TokenCache();

		} catch (Exception e) {
			LOGGER.severe(e.getMessage());
			ServiceException serviceException = new ServiceException("Error: " + e.getMessage());
			serviceException.initCause(e);
			throw serviceException;
		}
	}

	@Override
	public String getMimeType(Object value, Operation operation) throws ServiceException {
		return MIME_TYPE;
	}

	@Override
	public String getCapabilitiesElementName() {
		return NAME;
	}

	@Override
	public List<String> getCapabilitiesElementNames() {
		return Lists.newArrayList(NAME);
	}

	@Override
	public String getPreferredDisposition(Object value, Operation operation) {
		return DISPOSITION_ATTACH;
	}

	@Override
	protected String getExtension(FeatureCollectionResponse response) {
		return EXTENSION;
	}

	@Override
	public boolean canHandle(Operation operation) {

		Comparable<?> major = (Comparable<?>) operation.getService().getVersion().getMajor();
		// WFS 2.0
		if ((major instanceof Integer) && (((Comparable) 2).compareTo(major) == 0))
			return true;

		throw new ServiceException("Unsupported WFS version - only V2.0 is supported",
				ServiceException.MISSING_PARAMETER_VALUE);
	}

	@Override
	protected void write(FeatureCollectionResponse featureCollection, OutputStream output, Operation operation)
			throws IOException, ServiceException {

		Request request = Dispatcher.REQUEST.get();
		Map<String, Object> kvp = request.getKvp();

		String accessToken = (String) kvp.get("access_token");
		if (accessToken == null) {
			LOGGER.info("No 'access_token' in query. Looking in HTTP header...");
			String authorization = request.getHttpRequest().getHeader("Authorization");
			if (authorization == null) {
				LOGGER.severe("No 'access_token' in query and no Authorization header");
				throw new ServiceException("Must submit Bearer Access Token RFC 6750 compliant.");
			} else {
				String[] token = authorization.split(" ");
				if (token.length != 2) {
					LOGGER.severe("Authorization header could not be processed");
					throw new ServiceException("Authorization header could not be processed.");
				} else {
					if (!token[0].trim().equalsIgnoreCase("Bearer")) {
						LOGGER.severe("Authorization header must be of type Bearer");
						throw new ServiceException("Authorization header must be of type Bearer.");
					} else {
						accessToken = token[1].trim();
					}
				}
			}
		}

		String dekId = (String) kvp.get("key_id");
		// Test for UUID - the function will throw an exception if not a valid UUID
		if (dekId != null)
		    UUID.fromString(dekId);
					
		String keyChallenge = (String) kvp.get("key_challenge");
		if ((dekId == null) && (keyChallenge == null)) {
			LOGGER.severe("'key_challenge' missing");
			throw new ServiceException("Required parameter 'key_challenge' missing");
		}
		String keyChallengeMethod = (String) kvp.get("key_challenge_method");
		if ((dekId == null) && (keyChallengeMethod == null)) {
			LOGGER.severe("'key_challenge_method' missing");
			throw new ServiceException("Required parameter 'key_challenge_method' missing");
		}


		// Validate the access token
		if (!tokenCache.isActive(accessToken)) {
			LOGGER.severe("Access Token invalid");
			ServiceException serviceException = new ServiceException("Error: Access Token invalid");
			throw serviceException;
		}

		File file = File.createTempFile("geopkg", ".tmp.gpkg");
		GeoPackage geopkg = EncryptedGeoPackage.getGeoPackage(file);

		geopkg.init();
		setupExtension(geopkg);
		int dekIdx = 1;
		for (FeatureCollection collection : featureCollection.getFeatures()) {

			String kid = null;
			KmsProxy kms = new KmsProxy();
			
			try {
				if (dekId != null) {
					// the user specified a kid for an encryption key that we need to use
					kid = dekId;

					String dekString = kms.get(kid, accessToken);

					Map<String, Object> dekJSON = JSONObjectUtils.parse(dekString);
					SecretJWK jwk = OctetSequenceKey.parse(dekJSON);

					SecretKey key = jwk.toSecretKey();
					dek = new SecretKeySpec(key.getEncoded(), "AES");
					
					// Create a JWS from the DEK to be stored in the Encrypted GeoPackage
					JWTClaimsSet dekClaimsSet = new JWTClaimsSet.Builder()
							.subject((String) dekJSON.get("sub"))
							.audience((String) dekJSON.get("aud"))
							.issuer((String) dekJSON.get("issuer"))
							.expirationTime(new Date((long) dekJSON.get("expires") * 1000 /*ms*/))
							.claim("kid", kid)
							.claim("alg", (String) dekJSON.get("alg"))
							.claim("kurl", dekUrl + kid)
							.claim("iat", (long) dekJSON.get("issued_at"))
							.build();
					dekJWT = new SignedJWT(jwsHeader, dekClaimsSet);

					// Compute the RSA signature
					dekJWT.sign(signer);
					if (LOGGER.getLevel() == Level.FINE)
						LOGGER.fine("dek JWT: " + dekJWT.serialize());

				} else {

					// Generate a new key
					dek = keyGen.generateKey();

					EncryptionMethod encMethod = EncryptionMethod.parse(enc);
					OctetSequenceKey osk = new OctetSequenceKey.Builder(dek).build();
					Base64URL k = osk.getKeyValue();

					// Register DEK with KMS
					long now = Instant.now().getEpochSecond();
					long expires = now + 300 /* 5min */;

					kid = kms.put(k.toString(), encMethod.getName(), keyChallenge, keyChallengeMethod,
							tokenCache.getAud(accessToken), tokenCache.getClientId(), tokenCache.getSub(accessToken),
							expires, accessToken);
					if (LOGGER.getLevel() == Level.FINE)
						LOGGER.fine("kid from KMS: " + kid);

					// Create a JWS from the DEK to be stored in the Encrypted GeoPackage
					List<String> audience = new ArrayList<String>();
					audience.add(tokenCache.getAud(accessToken));
					JWTClaimsSet dekClaimsSet = new JWTClaimsSet.Builder()
							.subject(tokenCache.getSub(accessToken))
							.audience(audience)
							.issuer(tokenCache.getClientId())
							.expirationTime(new Date(expires * 1000))
							.claim("kid", kid)
							.claim("alg", encMethod.getName())
							.claim("kurl", dekUrl + kid)
							.claim("iat", now)
							.build();
					dekJWT = new SignedJWT(jwsHeader, dekClaimsSet);

					// Compute the RSA signature
					dekJWT.sign(signer);
					if (LOGGER.getLevel() == Level.FINE)
						LOGGER.fine("dek JWT: " + dekJWT.serialize());
				}

			} catch (Exception e1) {
				LOGGER.severe(e1.getMessage());
				ServiceException serviceException = new ServiceException("Error: " + e1.getMessage());
				serviceException.initCause(e1);
				throw serviceException;
			}
			FeatureEntry e = new FeatureEntry();

			if (!(collection instanceof SimpleFeatureCollection)) {
				throw new ServiceException("GeoPackage OutputFormat does not support Complex Features.");
			}

			SimpleFeatureCollection features = (SimpleFeatureCollection) collection;
			FeatureTypeInfo meta = lookupFeatureType(features);

			SimpleFeatureType schema = features.getSchema();
			GeometryDescriptor geometryDescriptor = schema.getGeometryDescriptor();
			GeometryType type = geometryDescriptor.getType();

			String geometryTypeName = null;
			Class<?> x = type.getBinding();
			geometryTypeName = x.getSimpleName();
			Geometries gType = Geometries.getForName(geometryTypeName);

			String geometryColumn = type.getName().getLocalPart();
			String featureTypeName = meta.getName();

			CoordinateReferenceSystem crs = type.getCoordinateReferenceSystem();
			CoordinateSystem cs = crs.getCoordinateSystem();
			String srsId = crs.getName().getCode();
			String srs = meta.getSRS();
			String authority = srs.split(":")[0];
			int srid = Integer.valueOf(srs.split(":")[1]);
			
			if (meta != null) {
				// initialize entry metadata
				e.setIdentifier(meta.getTitle());
				e.setTableName(featureTypeName);
				e.setDescription(abstractOrDescription(meta));
				e.setGeometryType(gType);
				e.setBounds(collection.getBounds());
				e.setLastChange(meta.getDateModified());
				e.setGeometryColumn(geometryColumn);
				e.setSrid(srid);
			}
			schema.getUserData().put(FeatureEntry.class, e);

			setMetadata(geopkg, e, crs);

			addFeatures(geopkg, e, features, operation, dek, dekIdx++);

			if (!"false".equals(System.getProperty(PROPERTY_INDEXED))) {
				geopkg.createSpatialIndex(e);
			}
		}

		geopkg.close();

		// write to output and delete temporary file
		InputStream temp = new FileInputStream(geopkg.getFile());
		IOUtils.copy(temp, output);
		output.flush();
		temp.close();
		geopkg.getFile().delete();
	}

	FeatureTypeInfo lookupFeatureType(SimpleFeatureCollection features) {
		FeatureType featureType = features.getSchema();
		if (featureType != null) {
			Catalog cat = gs.getCatalog();
			FeatureTypeInfo meta = cat.getFeatureTypeByName(featureType.getName());
			if (meta != null) {
				return meta;
			}

			LOGGER.fine("Unable to load feature type metadata for: " + featureType.getName());
		} else {
			LOGGER.fine("No feature type for collection, unable to load metadata");
		}

		return null;
	}

	String abstractOrDescription(FeatureTypeInfo meta) {
		return meta.getAbstract() != null ? meta.getAbstract() : meta.getDescription();
	}

	private void setMetadata(GeoPackage geopkg, FeatureEntry fe, CoordinateReferenceSystem crs) {
		try {
			Connection c = geopkg.getDataSource().getConnection();

			TimeZone tz = TimeZone.getTimeZone("GMT");
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC
			df.setTimeZone(tz);
			String nowAsISO = df.format(new Date());

			PreparedStatement ps = c.prepareStatement(
					"INSERT INTO gpkg_contents (table_name, data_type, identifier, description, last_change, min_x, min_y, max_x, max_y, srs_id) VALUES (?,?,?,?,?,?,?,?,?,?)");
			ps.setString(1, fe.getTableName());
			ps.setString(2, "features");
			ps.setString(3, fe.getTableName());
			ps.setString(4, "Encrypted Feature");
			ps.setString(5, nowAsISO);
			if (AxisDirection.EAST == crs.getCoordinateSystem().getAxis(0).getDirection())
			{
				ps.setDouble(6, fe.getBounds().getMinX());
				ps.setDouble(7, fe.getBounds().getMinY());
				ps.setDouble(8, fe.getBounds().getMaxX());
				ps.setDouble(9, fe.getBounds().getMaxY());
			}
			else
			{
				ps.setDouble(6, fe.getBounds().getMinY());
				ps.setDouble(7, fe.getBounds().getMinX());
				ps.setDouble(8, fe.getBounds().getMaxY());
				ps.setDouble(9, fe.getBounds().getMaxX());
			}
			ps.setInt(10, fe.getSrid());
			ps.execute();

			// Correct the default SRS definition in the GeoPackage that was created via init()
			ps = c.prepareStatement("UPDATE gpkg_spatial_ref_sys SET definition=?, description=? WHERE srs_id='4326'");
			ps.setString(1, crs.getCoordinateSystem().toString());
			ps.setString(2, "The axis order in GeoPackage using WKB is always lon/lat. This CRS definition describes the axis order for the geometry of the feature itself");
			ps.execute();

			
			ps = c.prepareStatement("INSERT OR IGNORE INTO gpkg_geometry_columns VALUES (?, ?, ?, ?, ?, ?);");
			ps.setString(1, fe.getTableName());
			ps.setString(2, fe.getGeometryColumn());
			ps.setString(3, fe.getGeometryType().getName());
			ps.setInt(4, fe.getSrid());
			ps.setByte(5, (byte) 0);
			ps.setByte(6, (byte) 0);
			ps.execute();

			ps = prepare(c, format(
					"CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY, fid TEXT, %s BLOB, data BLOB, key_id INTEGER, FOREIGN KEY(key_id) REFERENCES gpkg_ext_keys(id));",
					fe.getTableName(), fe.getGeometryColumn())).log(Level.FINE).statement();
			ps.execute();

			ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?);", "gpkg_extensions")).set(fe.getTableName())
					.set((String) null).set("sd_encrypted_features")
					.set("https://docs.ogc.org/per/21-064.html#GPKGExtension").set("read-write").log(Level.FINE)
					.statement();
			ps.execute();

			ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?, ?, ?);", "gpkg_data_columns"))
					.set(fe.getTableName()).set("data").set(fe.getTableName() + "-data").set("Encrypted Feature Data")
					.set("The encrypted data of the tile using symmetric cipher").set("application/octet-stream")
					.set((String) null).log(Level.FINE).statement();

			ps.execute();

			ps = c.prepareStatement(format("INSERT INTO %s (data) VALUES (?);", "gpkg_ext_keys"));
			ps.setString(1, dekJWT.serialize());

			ps.execute();

			c.close();

		} catch (SQLException ex) {
			LOGGER.severe(ex.getMessage());
			ServiceException serviceException = new ServiceException("Error: " + ex.getMessage());
			serviceException.initCause(ex);
			throw serviceException;
		}
	}

	private void setupExtension(GeoPackage geopkg) {
		try {
			Connection c = geopkg.getDataSource().getConnection();
			PreparedStatement ps = prepare(c, format(
					"CREATE TABLE %s (" + "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," + "data TEXT NOT NULL)",
					"gpkg_ext_keys")).log(Level.FINE).statement();
			ps.execute();

			ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?);", "gpkg_extensions")).set("gpkg_ext_keys")
					.set((String) null).set("sd_encrypted_features")
					.set("https://docs.ogc.org/per/21-064.html#GPKGExtension").set("read-write").log(Level.FINE)
					.statement();
			ps.execute();

			c.close();

			ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?, ?, ?);", "gpkg_data_columns"))
					.set("gpkg_ext_keys").set("data").set("gpkg_ext_keys-data").set("DEK Info")
					.set("The key can be fetched via kid or kurl").set("application/jose").set((String) null)
					.log(Level.FINE).statement();

			ps.execute();

		} catch (SQLException e1) {
			LOGGER.severe(e1.getMessage());
		}
	}

	private void addFeatures(GeoPackage geopkg, FeatureEntry fe, SimpleFeatureCollection features, Operation operation,
			SecretKey dek, int dekIdx) throws IOException {
		try {

			Connection c = geopkg.getDataSource().getConnection();
			final boolean oldAutoCommit = c.getAutoCommit();
			c.setAutoCommit(false);
			PreparedStatement ps = prepare(c, format("INSERT INTO %s (fid, %s, data, key_id) VALUES (?, ?, ?, ?)",
					fe.getTableName(), fe.getGeometryColumn())).statement();

			try (SimpleFeatureIterator it = features.features()) {
				while (it.hasNext()) {
					SimpleFeature sf = it.next();

					// Prepare the cipher channel
					cipher.init(Cipher.ENCRYPT_MODE, dek);

					ByteArrayOutputStream featureStream = new ByteArrayOutputStream();
					CipherOutputStream cout = new CipherOutputStream(featureStream, cipher);

					featureStream.write(cipher.getIV());
					writeFeature(sf, cout, operation, gs.getSettings().getNumDecimals(), false);
					cout.close();
					featureStream.flush();

					Geometry aGeom = null;
					final CoordinateSystem cs = sf.getType().getCoordinateReferenceSystem().getCoordinateSystem();
					if (cs.getAxis(0).getDirection() == AxisDirection.NORTH)
					{
						// we have to construct a new Geometry via WKT Reader to be able to switch the coordinates
						// The underlying implementation of sf.getDefaultGeometry() probably returns a copy of the
						// coordinate value => the original cannot be changed via apply()!
						final WKTReader reader = new WKTReader(); 
						aGeom = reader.read(((Geometry) sf.getDefaultGeometry()).toText());
						aGeom.apply(new InverseAxisCoordinateSequenceFilter(aGeom.getCoordinates().length));
						aGeom.geometryChanged();
					}
					else
					{
						aGeom = (Geometry) sf.getDefaultGeometry();
					}
					
					final WKBWriter wkbWriter = new WKBWriter(2);
					
					ByteArrayOutputStream bao = new ByteArrayOutputStream();
					byte flags = 0b0;
					if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN))
						flags = (byte) (flags | 0b0);
					else
						flags = (byte) (flags | 0b1);

					byte[] header = { 0x47 /* G */, 0x50 /* P */, 0x00 /* version */, flags };
					bao.write(header);
					bao.write(sridToByteArray(fe.getSrid()));
					bao.write(wkbWriter.write(aGeom));
					ps.setString(1, sf.getID());
					ps.setBytes(2, bao.toByteArray());
					ps.setBytes(3, featureStream.toByteArray());
					ps.setInt(4, dekIdx);
					ps.execute();
					bao.close();
				}
			} catch (Exception e) {
				c.rollback();
				LOGGER.severe(e.getMessage());
				ServiceException serviceException = new ServiceException("Error: " + e.getMessage());
				serviceException.initCause(e);
				throw serviceException;

			} finally {
				c.commit();
				c.setAutoCommit(oldAutoCommit);
				c.close();
			}
		} catch (Exception ex) {
			LOGGER.severe(ex.getMessage());
			ServiceException serviceException = new ServiceException("Error: " + ex.getMessage());
			serviceException.initCause(ex);
			throw serviceException;
		}
	}

	private byte[] sridToByteArray(int i) {
		final ByteBuffer bb = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE);
		bb.order(ByteOrder.nativeOrder());
		bb.putInt(i);
		return bb.array();
	}

	private void writeFeature(SimpleFeature simpleFeature, OutputStream featureStream, Operation operation,
			int numDecimals, boolean encodeMeasures) throws IOException {
		SimpleFeatureType fType;
		List<AttributeDescriptor> types;
		CoordinateReferenceSystem crs = null;

		Writer featureWriter = new BufferedWriter(
				new OutputStreamWriter(featureStream, gs.getGlobal().getSettings().getCharset()));
		final GeoJSONBuilder jsonWriter = new GeoJSONBuilder(featureWriter);
		jsonWriter.setNumberOfDecimals(numDecimals);
		jsonWriter.setEncodeMeasures(encodeMeasures);

		// start writing the JSON feature object
		jsonWriter.object();
		jsonWriter.key("type").value("feature");
		fType = simpleFeature.getFeatureType();
		types = fType.getAttributeDescriptors();
		// write the simple feature id
		jsonWriter.key("id").value(simpleFeature.getID());
		
		// set that axis order that should be used to write geometries
		GeometryDescriptor defaultGeomType = fType.getGeometryDescriptor();
		if (defaultGeomType != null) {
			CoordinateReferenceSystem featureCrs = defaultGeomType.getCoordinateReferenceSystem();
			jsonWriter.setAxisOrder(CRS.getAxisOrder(featureCrs));
			if (crs == null) {
				crs = featureCrs;
			}
		} else {
			// If we don't know, assume EAST_NORTH so that no swapping occurs
			jsonWriter.setAxisOrder(CRS.AxisOrder.EAST_NORTH);
		}
		
		// start writing the simple feature geometry JSON object
		Geometry aGeom = (Geometry) simpleFeature.getDefaultGeometry();
		if (aGeom != null || writeNullGeometries()) {
			jsonWriter.key("geometry");
			// Write the geometry, whether it is a null or not
			if (aGeom != null) {
				jsonWriter.writeGeom(aGeom);
			} else {
				jsonWriter.value(null);
			}
			if (defaultGeomType != null) {
				jsonWriter.key("geometry_name").value(defaultGeomType.getLocalName());
			}
		}
		
		// start writing feature properties JSON object
		jsonWriter.key("properties");
		jsonWriter.object();
		for (int j = 0; j < types.size(); j++) {
			Object value = simpleFeature.getAttribute(j);
			AttributeDescriptor ad = types.get(j);
			
			if (ad instanceof GeometryDescriptor) {
				// This is an area of the spec where they
				// decided to 'let convention evolve',
				// that is how to handle multiple
				// geometries. My take is to print the
				// geometry here if it's not the default.
				// If it's the default that you already
				// printed above, so you don't need it here.
				if (!ad.equals(defaultGeomType)) {
					if (value == null) {
						jsonWriter.key(ad.getLocalName());
						jsonWriter.value(null);
					} else {
						// if it was the default geometry, it has been written above
						// already
						jsonWriter.key(ad.getLocalName());
						jsonWriter.writeGeom((Geometry) value);
					}
				}
			} else  if (Date.class.isAssignableFrom(ad.getType().getBinding())
					&& TemporalUtils.isDateTimeFormatEnabled()) {
				// Temporal types print handling
				jsonWriter.key(ad.getLocalName());
				jsonWriter.value(TemporalUtils.printDate((Date) value));
			} else {
				jsonWriter.key(ad.getLocalName());
				if ((value instanceof Double && Double.isNaN((Double) value))
						|| value instanceof Float && Float.isNaN((Float) value)) {
					jsonWriter.value(null);
				} else if ((value instanceof Double && ((Double) value) == Double.POSITIVE_INFINITY)
						|| value instanceof Float && ((Float) value) == Float.POSITIVE_INFINITY) {
					jsonWriter.value("Infinity");
				} else if ((value instanceof Double && ((Double) value) == Double.NEGATIVE_INFINITY)
						|| value instanceof Float && ((Float) value) == Float.NEGATIVE_INFINITY) {
					jsonWriter.value("-Infinity");
				} else {
					jsonWriter.value(value);
				}
			}
		}
		jsonWriter.endObject(); // end the properties

		jsonWriter.endObject(); // end the feature

		featureWriter.flush();
	}

	protected boolean writeNullGeometries() {
		return true;
	}
	
	private class InverseAxisCoordinateSequenceFilter implements CoordinateSequenceFilter
	{
		
		private boolean isDone = false;
		private int lastIdx;
		private double tmp;
		
		public InverseAxisCoordinateSequenceFilter(int size)
		{
			this.isDone = false;
			this.lastIdx = size - 1;
		}
		@Override
		public void filter(CoordinateSequence seq, int i) {
			tmp = seq.getCoordinate(i).x;
			seq.getCoordinate(i).x = seq.getCoordinate(i).y;
			seq.getCoordinate(i).y = tmp;
			isDone = (i == lastIdx);
		}

		@Override
		public boolean isDone() {
			return isDone;
		}

		@Override
		public boolean isGeometryChanged() {
			return true;
		}
		
	}
	
}
