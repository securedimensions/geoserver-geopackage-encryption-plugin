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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.io.IOUtils;
import org.geoserver.catalog.ResourceInfo;
import org.geoserver.enc.KmsProxy;
import org.geoserver.enc.TokenCache;
import org.geoserver.gwc.GWC;
import org.geoserver.ows.Dispatcher;
import org.geoserver.ows.Request;
import org.geoserver.ows.util.OwsUtils;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.platform.ServiceException;
import org.geoserver.tiles.AbstractTilesGetMapOutputFormat;
import org.geoserver.wms.GetMapRequest;
import org.geoserver.wms.MapLayerInfo;
import org.geoserver.wms.RasterCleaner;
import org.geoserver.wms.WMS;
import org.geoserver.wms.WMSMapContent;
import org.geoserver.wms.WebMap;
import org.geoserver.wms.WebMapService;
import org.geoserver.wms.map.PNGMapResponse;
import org.geoserver.wms.map.RenderedImageMapResponse;
import org.geotools.geometry.jts.ReferencedEnvelope;
import org.geotools.geopkg.GeoPackage;
import org.geotools.geopkg.Tile;
import org.geotools.geopkg.TileEntry;
import org.geotools.geopkg.TileMatrix;
import org.geotools.referencing.CRS;
import org.geotools.util.logging.Logging;
import org.geowebcache.grid.Grid;
import org.geowebcache.grid.GridSet;
import org.geowebcache.grid.GridSubset;
import org.locationtech.jts.geom.Envelope;
import org.opengis.referencing.crs.CoordinateReferenceSystem;

import com.google.common.collect.Sets;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * WMS GetMap Output Format for Encrypted GeoPackage
 *
 * @author Andreas Matheus, Secure Dimensions GmbH
 */
public class GeoPackageGetMapOutputFormat extends AbstractTilesGetMapOutputFormat {

	static Logger LOGGER = Logging.getLogger("org.geoserver.geopkg-encrypted");

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
	
	public GeoPackageGetMapOutputFormat(WebMapService webMapService, WMS wms, GWC gwc) {
		super(MIME_TYPE, "." + EXTENSION, Sets.newHashSet(NAME), webMapService, wms, gwc);

		try {
			
			InputStream stream = getClass().getClassLoader().getResourceAsStream(
		            "META-INF/GeoPackageGetMapOutputFormat.properties");
			
			if (stream == null)
		        throw new ServiceException("GeoPackageGetMapOutputFormat.properties files not found");
		   
            Properties properties = new Properties();
            properties.load(stream);
            stream.close();
		            
            issuer = (String)properties.get("issuer");
            if (issuer == null)
            	throw new ServiceException("GeoPackageGetMapOutputFormat.properties missing parameter 'issuer'");

            jwkUrl = (String)properties.get("jwk_url");
            if (jwkUrl == null)
            	throw new ServiceException("GeoPackageGetMapOutputFormat.properties missing parameter 'jwk_url'");

            pemFileName = (String)properties.get("pem_file_name");
            if (pemFileName == null)
            	throw new ServiceException("GeoPackageGetMapOutputFormat.properties missing parameter 'pem_file_name'");
			
            pemKid = (String)properties.get("pem_kid");
            if (pemKid == null)
            	throw new ServiceException("GeoPackageGetMapOutputFormat.properties missing parameter 'pem_kid'");
			
            dekUrl = (String)properties.get("dek_url");
            if (dekUrl == null)
            	throw new ServiceException("GeoPackageGetMapOutputFormat.properties missing parameter 'dek_url'");
			
            enc = (String)properties.get("enc");
            if (enc == null)
            	throw new ServiceException("GeoPackageGetMapOutputFormat.properties missing parameter 'enc'");
			
			// generate a symmetric key
			int keySize = 128;
			KeyGenerator keyGen;
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(keySize);
			dek = keyGen.generateKey();

			InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(pemFileName);
			String pem = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
			RSAKey senderJWK = JWK.parseFromPEMEncodedObjects(pem).toRSAKey();
			jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(pemKid)
					.jwkURL(new URI(jwkUrl)).build();

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

	private class GeopackageWrapper implements TilesFile {

		GeoPackage geopkg;

		TileEntry e;

		public GeopackageWrapper(GeoPackage geopkg, TileEntry e) throws IOException {
			this.geopkg = geopkg;
			this.e = e;
		}

		public GeopackageWrapper() throws IOException {
			this(new GeoPackage(), new TileEntry());
			geopkg.init();
		}

		@Override
		public void setMetadata(String name, ReferencedEnvelope box, String imageFormat, int srid,
				List<MapLayerInfo> mapLayers, int[] minmax, GridSubset gridSubset)
				throws IOException, ServiceException {

			e.setTableName(name);
			if (mapLayers.size() == 1) {
				ResourceInfo r = mapLayers.get(0).getResource();
				if (e.getIdentifier() == null) {
					e.setIdentifier(r.getTitle());
				}
				if (e.getDescription() == null) {
					e.setDescription(r.getAbstract());
				}
			}
			e.setBounds(box);
			e.setSrid(srid);

			GridSet gridSet = gridSubset.getGridSet();
			for (int z = minmax[0]; z < minmax[1]; z++) {
				Grid g = gridSet.getGrid(z);

				TileMatrix m = new TileMatrix();
				m.setZoomLevel(z);
				m.setMatrixWidth((int) g.getNumTilesWide());
				m.setMatrixHeight((int) g.getNumTilesHigh());
				m.setTileWidth(gridSubset.getTileWidth());
				m.setTileHeight(gridSubset.getTileHeight());

				// TODO: not sure about this
				m.setXPixelSize(g.getResolution());
				m.setYPixelSize(g.getResolution());
				// m.setXPixelSize(gridSet.getPixelSize());
				// m.setYPixelSize(gridSet.getPixelSize());

				e.getTileMatricies().add(m);
			}

			// figure out the actual bounds of the tiles to be renderered
			if (LOGGER.getLevel() == Level.FINE) LOGGER.fine("Creating tile entry" + e.getTableName());
			geopkg.create(e);

			try {
				Connection c = geopkg.getDataSource().getConnection();

				PreparedStatement ps = prepare(c, format("CREATE TABLE %s ("
						+ "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," + "data TEXT NOT NULL)", "gpkg_ext_keys"))
								.log(Level.FINE).statement();
				ps.execute();

				ps = c.prepareStatement(format("INSERT INTO %s (data) VALUES (?);", "gpkg_ext_keys"));
				ps.setString(1, dekJWT.serialize());

				ps.execute();

				ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?);", "gpkg_extensions")).set("gpkg_ext_keys")
						.set((String) null).set("sd_encrypted_tiles").set("https://docs.ogc.org/per/21-064.html#GPKGExtension").set("read-write")
						.log(Level.FINE).statement();
				ps.execute();

				/* Adopt tiles table */
				ps = prepare(c, format("DROP TABLE %s", name)).log(Level.FINE).statement();
				ps.execute();

				ps = prepare(c,
						format("CREATE TABLE %s (" + "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
								+ "zoom_level INTEGER NOT NULL," + "tile_column INTEGER NOT NULL,"
								+ "tile_row INTEGER NOT NULL," + "data BLOB NOT NULL," + "key_id INTEGER,"
								+ "FOREIGN KEY(key_id) REFERENCES gpkg_ext_keys(id))", name)).log(Level.FINE)
										.statement();

				ps.execute();

				ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?);", "gpkg_extensions"))
						.set(name)
						.set((String) null).set("sd_encrypted_tiles").set("https://docs.ogc.org/per/21-064.html#GPKGExtension").set("read-write")
						.log(Level.FINE).statement();
				ps.execute();

				ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?, ?, ?);", "gpkg_data_columns"))
						.set(name)
						.set("data").set(name + "-data").set("Encrypted Tile Data")
						.set("The encrypted data of the tile using symmetric cipher").set("application/octet-stream")
						.set((String) null).log(Level.FINE).statement();

				ps.execute();

				ps = prepare(c, format("INSERT INTO %s VALUES (?, ?, ?, ?, ?, ?, ?);", "gpkg_data_columns"))
						.set("gpkg_ext_keys").set("data").set("gpkg_ext_keys-data").set("DEK Info")
						.set("The key can be fetched via kid or kurl").set("application/jose").set((String) null)
						.log(Level.FINE).statement();

				ps.execute();

				c.close();

			} catch (SQLException ex) {
				LOGGER.severe(ex.getMessage());
				ServiceException serviceException = new ServiceException("Error: " + ex.getMessage());
				serviceException.initCause(ex);
				throw serviceException;
			}
		}

		@Override
		public void addTile(int zoom, int x, int y, byte[] data) throws IOException {
			Tile t = new Tile();
			t.setZoom(zoom);
			t.setColumn(x);
			t.setRow(y);
			t.setData(data);
			// geopkg.add(geopkg,e, t);
			try (Connection cx = geopkg.getDataSource().getConnection();
					PreparedStatement ps = prepare(cx,
							format("INSERT INTO %s (zoom_level, tile_column,"
									+ " tile_row, data, key_id) VALUES (?,?,?,?,?)", e.getTableName()))
											.set(t.getZoom()).set(t.getColumn()).set(t.getRow()).set(t.getData()).set(1)
											.log(Level.FINE).statement()) {
				ps.execute();
			} catch (SQLException e) {
				throw new IOException(e);
			}
		}

		@Override
		public File getFile() {
			return geopkg.getFile();
		}

		@Override
		public void close() {
			geopkg.close();
		}
	}

	@Override
	public WebMap produceMap(WMSMapContent map) throws ServiceException, IOException {

		try {
			Request request = Dispatcher.REQUEST.get();		
			Map <String, Object> kvp = request.getKvp();
			
			String accessToken = (String)kvp.get("access_token");
			if (accessToken == null) {
				LOGGER.info("No 'access_token' in query. Looking in HTTP header...");
				String authorization = request.getHttpRequest().getHeader("Authorization");
				if (authorization == null)
				{
					LOGGER.severe("No 'access_token' in query and no Authorization header");
					throw new ServiceException("Must submit Bearer Access Token RFC 6750 compliant.");
				}
				else
				{
					String []token = authorization.split(" ");
					if (token.length != 2)
					{
						LOGGER.severe("Authorization header could not be processed");
						throw new ServiceException("Authorization header could not be processed.");
					}
					else
					{
						if (!token[0].trim().equalsIgnoreCase("Bearer"))
						{
							LOGGER.severe("Authorization header must be of type Bearer");
							throw new ServiceException("Authorization header must be of type Bearer.");
						}
						else
						{
							accessToken = token[1].trim();
						}
					}
				}
			}

			String keyChallenge = (String)kvp.get("key_challenge");
			if (keyChallenge == null) {
				LOGGER.severe("'key_challenge' missing");
				throw new ServiceException("Required parameter 'key_challenge' missing");
			}
			String keyChallengeMethod = (String)kvp.get("key_challenge_method");
			if (keyChallengeMethod == null) {
				LOGGER.severe("'key_challenge_method' missing");
				throw new ServiceException("Required parameter 'key_challenge_method' missing");
			}

			// Validate the access token
			if (!tokenCache.isActive(accessToken)) {
				LOGGER.severe("Access Token invalid");
				ServiceException serviceException = new ServiceException("Error: Access Token invalid");
				throw serviceException;
			}

			// Register DEK with KMS
			KmsProxy kms = new KmsProxy();
			
			EncryptionMethod encMethod = EncryptionMethod.parse(enc);
			OctetSequenceKey jwk = new OctetSequenceKey.Builder(dek).build();
			Base64URL k = jwk.getKeyValue();

			long now = Instant.now().getEpochSecond();
			long expires = now + 300 /* 5min*/;
			String kid = kms.put(k.toString(), encMethod.getName(), keyChallenge, keyChallengeMethod, tokenCache.getAud(accessToken),
					tokenCache.getClientId(), tokenCache.getSub(accessToken), expires, accessToken);

			if (LOGGER.getLevel() == Level.FINE) LOGGER.fine("kid from KMS: " + kid);

			// Create a JWS from the DEK to be stored in the DCS GeoPackage
			List<String> audience = new ArrayList<String>();
			audience.add(tokenCache.getAud(accessToken));
			JWTClaimsSet dekClaimsSet = new JWTClaimsSet.Builder().subject(tokenCache.getSub(accessToken)).audience(audience)
					.issuer(issuer).expirationTime(new Date(expires)).claim("kid", kid)
					.claim("alg", encMethod.getName())
					.claim("kurl", dekUrl + kid).claim("iat", now).build();
			dekJWT = new SignedJWT(jwsHeader, dekClaimsSet);

			// Compute the RSA signature
			dekJWT.sign(signer);
			if (LOGGER.getLevel() == Level.FINE) LOGGER.fine("dek JWT: " + dekJWT.serialize());

		} catch (Exception ex) {
			LOGGER.severe(ex.getMessage());
			ServiceException serviceException = new ServiceException("Error: " + ex.getMessage());
			serviceException.initCause(ex);
			throw serviceException;
		}

		map.getRequest().getFormatOptions().put("flipy", "true");
		
		// The WMS request has set format=application/gpkg+dcs => No other parameter available to control the image format.
		// So we store all tiles in PNG format
		map.getRequest().setFormat("image/png");
		
		return super.produceMap(map);
	}

	@Override
	protected TilesFile createTilesFile() throws IOException {
		return new GeopackageWrapper();
	}

	/** Add tiles to an existing GeoPackage */
	public void addTiles(GeoPackage geopkg, TileEntry e, GetMapRequest req, String name) throws IOException {
		addTiles(new GeopackageWrapper(geopkg, e), req, name);
	}

	/**
	 * Special method to add tiles using Geopackage's own grid matrix system rather
	 * than GWC gridsubsets
	 */
	public void addTiles(GeoPackage geopkg, TileEntry e, GetMapRequest request, List<TileMatrix> matrices, String name)
			throws IOException, ServiceException {

		List<MapLayerInfo> mapLayers = request.getLayers();

		SortedMap<Integer, TileMatrix> matrixSet = new TreeMap<Integer, TileMatrix>();
		for (TileMatrix matrix : matrices) {
			matrixSet.put(matrix.getZoomLevel(), matrix);
		}

		if (mapLayers.isEmpty()) {
			return;
		}

		// Get the RasterCleaner object
		RasterCleaner cleaner = GeoServerExtensions.bean(RasterCleaner.class);

		// figure out the actual bounds of the tiles to be renderered
		ReferencedEnvelope bbox = bounds(request);

		// set metadata
		e.setTableName(name);
		e.setBounds(bbox);
		e.setSrid(srid(request));
		e.getTileMatricies().addAll(matrices);
		if (LOGGER.getLevel() == Level.FINE) LOGGER.fine("Creating tile entry" + e.getTableName());
		geopkg.create(e);

		GetMapRequest req = new GetMapRequest();
		OwsUtils.copy(request, req, GetMapRequest.class);
		req.setLayers(mapLayers);

		Map formatOpts = req.getFormatOptions();

		Integer minZoom = null;
		if (formatOpts.containsKey("min_zoom")) {
			minZoom = Integer.parseInt(formatOpts.get("min_zoom").toString());
		}

		Integer maxZoom = null;
		if (formatOpts.containsKey("max_zoom")) {
			maxZoom = Integer.parseInt(formatOpts.get("max_zoom").toString());
		} else if (formatOpts.containsKey("num_zooms")) {
			maxZoom = minZoom + Integer.parseInt(formatOpts.get("num_zooms").toString());
		}

		if (minZoom != null || maxZoom != null) {
			matrixSet = matrixSet.subMap(minZoom, maxZoom);
		}

		String imageFormat = formatOpts.containsKey("format") ? parseFormatFromOpts(formatOpts)
				: findBestFormat(request);
		req.setFormat(imageFormat);

		CoordinateReferenceSystem crs = getCoordinateReferenceSystem(request);
		if (crs == null) {
			String srs = getSRS(request);
			try {
				crs = CRS.decode(srs);
			} catch (Exception ex) {
				throw new ServiceException(ex);
			}
		}
		double xSpan = crs.getCoordinateSystem().getAxis(0).getMaximumValue()
				- crs.getCoordinateSystem().getAxis(0).getMinimumValue();
		double ySpan = crs.getCoordinateSystem().getAxis(1).getMaximumValue()
				- crs.getCoordinateSystem().getAxis(1).getMinimumValue();
		double xOffset = crs.getCoordinateSystem().getAxis(0).getMinimumValue();
		double yOffset = crs.getCoordinateSystem().getAxis(1).getMinimumValue();

		req.setCrs(crs);

		// column and row bounds
		Integer minColumn = null, maxColumn = null, minRow = null, maxRow = null;
		if (formatOpts.containsKey("min_column")) {
			minColumn = Integer.parseInt(formatOpts.get("min_column").toString());
		}
		if (formatOpts.containsKey("max_column")) {
			maxColumn = Integer.parseInt(formatOpts.get("max_column").toString());
		}
		if (formatOpts.containsKey("min_row")) {
			minRow = Integer.parseInt(formatOpts.get("min_row").toString());
		}
		if (formatOpts.containsKey("max_row")) {
			maxRow = Integer.parseInt(formatOpts.get("max_row").toString());
		}

		for (TileMatrix matrix : matrixSet.values()) {

			req.setWidth(matrix.getTileWidth());
			req.setHeight(matrix.getTileHeight());

			// long[] intersect = gridSubset.getCoverageIntersection(z, bbox);
			double resX = xSpan / matrix.getMatrixWidth();
			double resY = ySpan / matrix.getMatrixHeight();

			long minX = Math.round(Math.floor((bbox.getMinX() - xOffset) / resX));
			long minY = Math.round(Math.floor((bbox.getMinY() - yOffset) / resY));
			long maxX = Math.round(Math.ceil((bbox.getMaxX() - xOffset) / resX));
			long maxY = Math.round(Math.ceil((bbox.getMaxY() - yOffset) / resY));

			minX = minColumn == null ? minX : Math.max(minColumn, minX);
			maxX = maxColumn == null ? maxX : Math.min(maxColumn, maxX);
			minY = minRow == null ? minY : Math.max(minRow, minY);
			maxY = maxRow == null ? maxY : Math.min(maxRow, maxY);

			for (long x = minX; x < maxX; x++) {
				for (long y = minY; y < maxY; y++) {
					req.setBbox(new Envelope(xOffset + x * resX, xOffset + (x + 1) * resX, yOffset + y * resY,
							yOffset + (y + 1) * resY));
					WebMap result = webMapService.getMap(req);
					Tile t = new Tile();
					t.setZoom(matrix.getZoomLevel());
					t.setColumn((int) x);
					t.setRow((int) y);
					t.setData(toBytes(result));
					addTile(geopkg, e, t);
					// Cleanup
					cleaner.finished(null);
				}
			}
		}
	}

	@Override
	protected byte[] toBytes(WebMap map) throws IOException {

		// Prepare the cipher channel
		try {
			cipher.init(Cipher.ENCRYPT_MODE, dek);
		
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			CipherOutputStream cout = new CipherOutputStream(bout, cipher);
			bout.write(cipher.getIV());
			
			// At the moment, the format is fixed to PNG
			RenderedImageMapResponse response = new PNGMapResponse(wms);
			response.write(map, cout, null);
	
			cout.close();
			bout.flush();
			return bout.toByteArray();
		} catch (InvalidKeyException e) {
			LOGGER.severe(e.getMessage());
			throw new IOException(e);
		} 

	}

	private void addTile(GeoPackage geopkg, TileEntry entry, Tile tile) throws IOException {
		try (Connection cx = geopkg.getDataSource().getConnection();
				PreparedStatement ps = prepare(cx,
						format("INSERT INTO %s (zoom_level, tile_column,"
								+ " tile_row, data, key_id) VALUES (?,?,?,?,?)", entry.getTableName()))
										.set(tile.getZoom()).set(tile.getColumn()).set(tile.getRow())
										.set(tile.getData()).set(1).log(Level.FINE).statement()) {
			ps.execute();
		} catch (SQLException e) {
			LOGGER.severe(e.getMessage());
			throw new IOException(e);
		}
	}
}
