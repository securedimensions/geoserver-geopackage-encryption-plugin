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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
import org.geoserver.wms.map.RawMap;
import org.geoserver.wms.map.RenderedImageMapResponse;
import org.geotools.geometry.jts.ReferencedEnvelope;
import org.geotools.geopkg.GeoPackage;
import org.geotools.geopkg.Tile;
import org.geotools.geopkg.TileEntry;
import org.geotools.geopkg.TileMatrix;
import org.geotools.map.Layer;
import org.geotools.referencing.CRS;
import org.geotools.util.logging.Logging;
import org.geowebcache.grid.BoundingBox;
import org.geowebcache.grid.Grid;
import org.geowebcache.grid.GridSet;
import org.geowebcache.grid.GridSubset;
import org.locationtech.jts.geom.Envelope;
import org.opengis.referencing.crs.CoordinateReferenceSystem;

import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
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
 * WMS GetMap Output Format for Encrypted GeoPackage
 *
 * @author Andreas Matheus, Secure Dimensions GmbH
 */
public class GeoPackageGetMapOutputFormat extends AbstractTilesGetMapOutputFormat {

	static Logger LOGGER = Logging.getLogger("org.geoserver.geopkg-encrypted");

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
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(keySize);

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

		public void setMetadata(String name, ReferencedEnvelope box, String imageFormat, int srid,
				List<MapLayerInfo> mapLayers, int[] minmax, GridSubset gridSubset, String kid)
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
						+ "id TEXT NOT NULL PRIMARY KEY," + "data TEXT NOT NULL)", "gpkg_ext_keys"))
								.log(Level.FINE).statement();
				ps.execute();
				
				ps = c.prepareStatement(format("INSERT INTO %s (id, data) VALUES (?, ?);", "gpkg_ext_keys"));
				ps.setString(1, kid);
				ps.setString(2, dekJWT.serialize());

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
								+ "tile_row INTEGER NOT NULL," + "tile_data BLOB NOT NULL," + "kid TEXT,"
								+ "FOREIGN KEY(kid) REFERENCES gpkg_ext_keys(id))", name)).log(Level.FINE)
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

		public void addTile(int zoom, int x, int y, byte[] data, String kid) throws IOException {
			Tile t = new Tile();
			t.setZoom(zoom);
			t.setColumn(x);
			t.setRow(y);
			t.setData(data);
			// geopkg.add(geopkg,e, t);
			try (Connection cx = geopkg.getDataSource().getConnection();
					PreparedStatement ps = prepare(cx,
							format("INSERT INTO %s (zoom_level, tile_column,"
									+ " tile_row, tile_data, kid) VALUES (?,?,?,?,?)", e.getTableName()))
											.set(t.getZoom()).set(t.getColumn()).set(t.getRow()).set(t.getData()).set(kid)
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

		@Override
		public void addTile(int zoom, int x, int y, byte[] data) throws IOException, ServiceException {
			// TODO Auto-generated method stub
			;
		}

		@Override
		public void setMetadata(String name, ReferencedEnvelope box, String imageFormat, int srid,
				List<MapLayerInfo> mapLayers, int[] minmax, GridSubset gridSubset)
				throws IOException, ServiceException {
			// TODO Auto-generated method stub
			
		}
	}

	@Override
	public WebMap produceMap(WMSMapContent map) throws ServiceException, IOException {


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

		map.getRequest().getFormatOptions().put("flipy", "true");
		
		// The WMS request has set format=application/gpkg+dcs => No other parameter available to control the image format.
		// So we store all tiles in PNG format
		map.getRequest().setFormat("image/png");
		
		map.getUserData().put("kid", kid);
		
		return produceMapX(map);
	}

    private WebMap produceMapX(WMSMapContent map) throws ServiceException, IOException {
    	GeopackageWrapper tiles = new GeopackageWrapper();
        addTiles(tiles, map);
        tiles.close();

        final File dbFile = tiles.getFile();
        final BufferedInputStream bin = new BufferedInputStream(new FileInputStream(dbFile));

        RawMap result =
                new RawMap(map, bin, getMimeType()) {
                    @Override
                    public void writeTo(OutputStream out) throws IOException {
                        String dbFilename = getAttachmentFileName();
                        if (dbFilename != null) {
                            dbFilename =
                                    dbFilename.substring(0, dbFilename.length() - 4) + extension;
                        } else {
                            // this shouldn't really ever happen, but fallback anyways
                            dbFilename = "tiles" + extension;
                        }

                        IOUtils.copy(bin, out);
                        out.flush();
                        bin.close();
                        try {
                            dbFile.delete();
                        } catch (Exception e) {
                            LOGGER.log(
                                    Level.WARNING,
                                    "Error deleting file: " + dbFile.getAbsolutePath(),
                                    e);
                        }
                    }
                };

        result.setContentDispositionHeader(map, extension, true);
        return result;
    }

    protected void addTiles(GeopackageWrapper tiles, WMSMapContent map)
            throws ServiceException, IOException {
        GetMapRequest req = map.getRequest();

        List<Layer> layers = map.layers();
        List<MapLayerInfo> mapLayers = req.getLayers();

        Preconditions.checkState(
                layers.size() == mapLayers.size(),
                "Number of map layers not same as number of rendered layers");

        addTiles(tiles, req, map.getTitle(), (String)map.getUserData().get("kid"));
    }

    protected void addTiles(GeopackageWrapper tiles, GetMapRequest req, String name, String kid)
            throws ServiceException, IOException {
        List<MapLayerInfo> mapLayers = req.getLayers();

        // list of layers to render directly and include as tiles
        List<MapLayerInfo> tileLayers = new ArrayList<MapLayerInfo>();

        // tiled mode means render all as map tile layer
        tileLayers.addAll(mapLayers);

        addTiles(tiles, tileLayers, req, name, kid);
    }

    /** Add the tiles */
    protected void addTiles(
    		GeopackageWrapper tiles, List<MapLayerInfo> mapLayers, GetMapRequest request, String name, String kid)
            throws IOException, ServiceException {

        if (mapLayers.isEmpty()) {
            return;
        }

        // Get the RasterCleaner object
        RasterCleaner cleaner = GeoServerExtensions.bean(RasterCleaner.class);

        // figure out a name for the file entry
        String tileEntryName = null;
        Map formatOpts = request.getFormatOptions();
        if (formatOpts.containsKey("tileset_name")) {
            tileEntryName = (String) formatOpts.get("tileset_name");
        }
        if (name != null) {
            tileEntryName = name;
        }
        if (tileEntryName == null) {
            Iterator<MapLayerInfo> it = mapLayers.iterator();
            tileEntryName = "";
            while (it.hasNext()) {
                tileEntryName += it.next().getLayerInfo().getName() + "_";
            }
            tileEntryName = tileEntryName.substring(0, tileEntryName.length() - 1);
        }

        // figure out the actual bounds of the tiles to be renderered
        BoundingBox bbox = bbox(request);
        GridSubset gridSubset = findBestGridSubset(request);
        int[] minmax = findMinMaxZoom(gridSubset, request);
        // ReferencedEnvelope bounds = new ReferencedEnvelope(findTileBounds(gridSubset, bbox,
        //        minmax[0]), getCoordinateReferenceSystem(map));

        // create a prototype getmap request
        GetMapRequest req = new GetMapRequest();
        OwsUtils.copy(request, req, GetMapRequest.class);
        req.setLayers(mapLayers);

        String imageFormat =
                formatOpts.containsKey("format")
                        ? parseFormatFromOpts(formatOpts)
                        : findBestFormat(request);

        req.setFormat(imageFormat);
        req.setWidth(gridSubset.getTileWidth());
        req.setHeight(gridSubset.getTileHeight());
        req.setCrs(getCoordinateReferenceSystem(request));

        // store metadata
        tiles.setMetadata(
                tileEntryName,
                bounds(request),
                imageFormat,
                srid(request),
                mapLayers,
                minmax,
                gridSubset,
                kid);

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

        // flag determining if tile row indexes we store in database should be inverted
        boolean flipy = Boolean.valueOf((String) formatOpts.get("flipy"));
        for (int z = minmax[0]; z < minmax[1]; z++) {
            long[] intersect = gridSubset.getCoverageIntersection(z, bbox);
            long minX = minColumn == null ? intersect[0] : Math.max(minColumn, intersect[0]);
            long maxX = maxColumn == null ? intersect[2] : Math.min(maxColumn, intersect[2]);
            long minY = minRow == null ? intersect[1] : Math.max(minRow, intersect[1]);
            long maxY = maxRow == null ? intersect[3] : Math.min(maxRow, intersect[3]);
            for (long x = minX; x <= maxX; x++) {
                for (long y = minY; y <= maxY; y++) {
                    BoundingBox box = gridSubset.boundsFromIndex(new long[] {x, y, z});
                    req.setBbox(
                            new Envelope(
                                    box.getMinX(), box.getMaxX(), box.getMinY(), box.getMaxY()));
                    WebMap result = webMapService.getMap(req);

                    tiles.addTile(
                            z,
                            (int) x,
                            (int) (flipy ? gridSubset.getNumTilesHigh(z) - (y + 1) : y),
                            toBytes(result),
                            kid);
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

	@Override
	protected TilesFile createTilesFile() throws IOException {
		// TODO Auto-generated method stub
		return null;
	}
}
