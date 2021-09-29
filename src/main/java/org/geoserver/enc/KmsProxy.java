/**
 * Proxy to support DEK registration with KMS for DCS GeoPackage
 *
 * @author Andreas Matheus, Secure Dimensions GmbH
 */
package org.geoserver.enc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import org.apache.commons.io.IOUtils;
import org.geoserver.platform.ServiceException;

public class KmsProxy {

    private final Logger LOGGER = org.geotools.util.logging.Logging.getLogger(this.getClass());

    private URL url;

    public KmsProxy() throws ServiceException {

		InputStream stream = getClass().getClassLoader().getResourceAsStream(
	            "META-INF/KmsProxy.properties");
		
		if (stream == null)
	        throw new ServiceException("KmsProxy.properties files not found");
	   
	    try {
	            Properties properties = new Properties();
	            properties.load(stream);
	            stream.close();
	            
	            String dekRegisterEndpoint = (String)properties.get("dek_registration_endpoint");
	            if (dekRegisterEndpoint == null)
	            	throw new ServiceException("KmsProxy.properties missing parameter 'dek_registration_endpoint'");

	            this.url = new URL(dekRegisterEndpoint);
	            
	    }
	    catch (IOException e)
	    {
	    	throw new ServiceException(e);
	    }
    	
   }

    public String put(
            String k,
            String alg,
            String challenge,
            String challengeMethod,
            String aud,
            String iss,
            String sub,
            long expires,
            String accessToken)
            throws Exception {
        String kid = null;

        Map<String, String> data = new HashMap<String, String>();

        data.put("k", k);
        data.put("kty", "oct");
        data.put("alg", alg);
        data.put("key_challenge", challenge);
        data.put("key_challenge_method", challengeMethod);
        data.put("aud", aud);
        data.put("issuer", iss);
        data.put("sub", sub);
        data.put("expires", String.valueOf(expires));

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

        // Convert the requestData into bytes
        byte[] requestDataByes = requestData.toString().getBytes("UTF-8");

        kid = send(requestDataByes, accessToken);

        if (kid == null) throw new IOException("kid null");

        return kid;
    }

    private String send(byte[] request, String accessToken) throws Exception {
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("POST");

        con.setRequestProperty("Content-length", String.valueOf(request.length));
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Authorization", "Bearer " + accessToken);
        con.setDoOutput(true);
        con.setDoInput(true);

        DataOutputStream output = new DataOutputStream(con.getOutputStream());
        output.write(request);

        output.close();
        int status = con.getResponseCode();
        if (status == 401) {

            con = (HttpsURLConnection) url.openConnection();
            con.setRequestMethod("POST");

            con.setRequestProperty("Content-length", String.valueOf(request.length));
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("Authorization", "Bearer " + accessToken);
            con.setDoOutput(true);
            con.setDoInput(true);

            output = new DataOutputStream(con.getOutputStream());
            output.write(request);

            output.close();
        }

        if (con.getResponseCode() == 200) {
            DataInputStream inputStream = new DataInputStream(con.getInputStream());
            String response = IOUtils.toString(inputStream, StandardCharsets.UTF_8);

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(response);
            String kid = jsonNode.get("kid").asText();

            return kid;
        } else {

            return null;
        }
    }
}
