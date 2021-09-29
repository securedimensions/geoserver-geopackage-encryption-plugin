/**
 * Access Token Cache
 *
 * @author Andreas Matheus, Secure Dimensions GmbH
 */
package org.geoserver.enc;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.apache.commons.io.IOUtils;
import org.eclipse.emf.ecore.xml.type.internal.DataValue.Base64;
import org.geoserver.platform.ServiceException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TokenCache {

	static final Logger LOGGER = org.geotools.util.logging.Logging.getLogger("org.geoserver.dcs.TokenInfo");

	static private Long DEFAULT_EXPIRY = Long.valueOf(60 /* seconds */);
	static private long DEFAULT_FRACTION = 100 /* th */;
	static private long CLEANUP_INTERVAL = 30 /* seconds */;

	private String clientId = null;
	private String clientSecret = null;

	private URL tokenInfoURL = null;

	private WeakConcurrentHashMap<String, AccessToken> tokenCache = null;

	private class AccessToken {
		private Long tokenExpires;
		private Long cacheExpires;
		private JsonNode tokenInfo;

		public AccessToken(JsonNode tokenInfo) {
			if (tokenInfo.has("exp")) {
				// The access token is cached for 100th of the expires. E.g. token expires in
				// 1800 seconds, then it's cached for the minimum of 18 seconds
				// The actual storage time is the calculated cache time + the time until the
				// cleanup runs. So in case the cleanup runs every
				// 30 seconds, then the storage time for the example above is 18 seconds
				// (the cleanup runs 18 seconds after the token was added) and up
				// to 48 seconds (the cleanup just ran exactly before the token was added).
				// For performance reasons, the expires is not updated on subsequent reads.
				// This ensures that burst requests that may come from a visualization client
				// use cached token but also ensures that cancelled tokens are detected after at least 48 seconds
				// for the example above
				this.tokenExpires = tokenInfo.findValue("exp").asLong();
				long expiresIn = this.tokenExpires - Instant.now().getEpochSecond();
				this.cacheExpires = Instant.now().getEpochSecond() + (expiresIn / DEFAULT_FRACTION);
				this.tokenInfo = tokenInfo;
			} else {
				this.cacheExpires = Long.valueOf(DEFAULT_EXPIRY);
				this.tokenExpires = Long.valueOf(0);
				this.tokenInfo = tokenInfo;
			}
		}

		public long getTokenExpires() {
			return tokenExpires;
		}

		public long getCacheExpires() {
			return cacheExpires;
		}

		public String getSub() {
			return tokenInfo.findValue("sub").textValue();
		}

		public String getAud() {
			return tokenInfo.findValue("client_id").textValue();
		}

		public JsonNode getTokenInfo() {
			return tokenInfo;
		}

		public String toString() {
			return "cache expires=" + cacheExpires + ", tokenInfo=" + tokenInfo.toString();
		}
	}

	private static class WeakConcurrentHashMap<K, V> extends ConcurrentHashMap<K, V> {

		private static final long serialVersionUID = 1L;

		private static WeakConcurrentHashMap<String, AccessToken> instance;

		private long expiryInMillis = CLEANUP_INTERVAL * 1000 /* 60 sec */;

		public static synchronized WeakConcurrentHashMap<?, ?> getInstance() {
			if (WeakConcurrentHashMap.instance == null) {
				WeakConcurrentHashMap.instance = new WeakConcurrentHashMap<String, AccessToken>();
			}
			return WeakConcurrentHashMap.instance;
		}

		private WeakConcurrentHashMap() {
			initialize();
		}

		void initialize() {
			new CleanerThread().start();
		}

		@Override
		public V put(K key, V value) {
			LOGGER.info("Inserting : " + key + " : " + value);
			V returnVal = super.put(key, value);
			return returnVal;
		}

		@Override
		public void putAll(Map<? extends K, ? extends V> m) {
			for (K key : m.keySet()) {
				put(key, m.get(key));
			}
		}

		@Override
		public V putIfAbsent(K key, V value) {
			if (!containsKey(key))
				return put(key, value);
			else
				return get(key);
		}

		class CleanerThread extends Thread {
			@Override
			public void run() {
				LOGGER.info(
						"Initiating Token Cache Cleaner Thread to run every " + expiryInMillis / 1000 + " seconds...");
				while (true) {
					try {
						Thread.sleep(expiryInMillis);
						cleanMap();
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}

			private void cleanMap() {
				LOGGER.info("Cleaning Token Cache...");
				long currentTime = Instant.now().getEpochSecond();
				for (K key : keySet()) {
					AccessToken token = (AccessToken) get(key);
					if (token == null)
						continue;

					long expires = token.getCacheExpires();
					if (currentTime > expires) {
						V value = remove(key);
						LOGGER.info("Removing : " + key + " : " + value);
					}
				}
				LOGGER.info("Cleaning Token Cache finished.");
			}
		}
	}

	public TokenCache() throws ServiceException {
		InputStream stream = getClass().getClassLoader().getResourceAsStream("META-INF/TokenCache.properties");

		if (stream == null)
			throw new ServiceException("TokenCache.properties files not found");

		try {
			Properties properties = new Properties();
			properties.load(stream);
			stream.close();

			clientId = (String) properties.get("client_id");
			if (clientId == null)
				throw new ServiceException("TokenCache.properties missing parameter 'client_id'");

			clientSecret = (String) properties.get("client_secret");
			if (clientSecret == null)
				throw new ServiceException("TokenCache.properties missing parameter 'client_secret'");

			String tokenInfoEndpoint = (String) properties.get("token_info_endpoint");
			if (tokenInfoEndpoint == null)
				throw new ServiceException("TokenCache.properties files not found");
			else
				tokenInfoURL = new URL(tokenInfoEndpoint);

		} catch (IOException e) {
			throw new ServiceException(e);
		}

		this.tokenCache = (WeakConcurrentHashMap<String, AccessToken>) WeakConcurrentHashMap.getInstance();
	}

	public String getClientId() {
		return clientId;
	}

	public boolean isActive(String accessTokenId) {

		AccessToken token = tokenCache.get(accessTokenId);
		long currentTime = Instant.now().getEpochSecond();
		if (token == null) {
			JsonNode tokenInfo = getTokenInfo(accessTokenId);
			token = new AccessToken(tokenInfo);
			if (currentTime <= token.getTokenExpires())
				tokenCache.put(accessTokenId, token);
		}

		return (currentTime <= token.getTokenExpires());
	}

	public String getAud(String accessTokenId) {
		AccessToken token = tokenCache.get(accessTokenId);
		return (token != null) ? token.getAud() : null;
	}

	public String getSub(String accessTokenId) {
		AccessToken token = tokenCache.get(accessTokenId);
		return (token != null) ? token.getSub() : null;
	}

	private JsonNode getTokenInfo(String accessToken) {
		try {
			HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
				@Override
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			HttpsURLConnection con = (HttpsURLConnection) tokenInfoURL.openConnection();

			byte[] request = getRequest(accessToken);
			con.setRequestProperty("Content-length", String.valueOf(request.length));
			con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			con.setRequestProperty("Authorization",
					"Basic " + Base64.encode(new String(clientId + ":" + clientSecret).getBytes()));
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestMethod("POST");

			con.connect();

			DataOutputStream output = new DataOutputStream(con.getOutputStream());
			output.write(request);
			output.close();

			DataInputStream inputStream = new DataInputStream(con.getInputStream());
			String response = IOUtils.toString(inputStream, StandardCharsets.UTF_8);

			ObjectMapper objectMapper = new ObjectMapper();

			JsonNode tokenInfo = objectMapper.readTree(response);
			LOGGER.info("TokenInfo: " + tokenInfo);
			return tokenInfo;
		} catch (Exception e) {
			throw new ServiceException("Exception", ServiceException.NO_APPLICABLE_CODE);
		}
	}

	private byte[] getRequest(String accessToken) throws UnsupportedEncodingException {

		Map<String, String> data = new HashMap<String, String>();

		data.put("token", accessToken);
		data.put("token_type_hint", "access_token");

		// Instantiate a requestData object to store our data
		StringBuilder requestData = new StringBuilder();

		for (Map.Entry<String, String> param : data.entrySet()) {
			if (requestData.length() != 0) {
				requestData.append('&');
			}
			// Encode the parameter based on the parameter map we've defined
			// and append the values from the map to form a single parameter
			requestData.append(param.getKey());
			requestData.append('=');
			requestData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
		}

		String request = requestData.toString();
		LOGGER.fine("TokenInfo request: " + request);
		// Convert the requestData into bytes
		return request.getBytes("UTF-8");
	}
}
