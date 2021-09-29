/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.enc.geopkg;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.geotools.geopkg.GeoPackage;
import org.geotools.jdbc.JDBCDataStoreFactory;
import org.sqlite.SQLiteConfig;

/**
 * Encrypted GeoPackage
 *
 * @author Andreas Matheus, Secure Dimensions GmbH
 */

public class EncryptedGeoPackage extends GeoPackage {

    /** package file extension */
    public static final String EXTENSION = "geopackage+encrypted";

    /** format mime type */
    public static final String MIME_TYPE = "application/geopackage+sqlite3;profile=encrypted";

    /** Name */
    public static final String NAME = "Encrypted GeoPackage";
    
    public EncryptedGeoPackage() throws IOException {
        super();
    }
    
    /**
     * Initialize a GeoPackage connection with top speed for single user writing
     *
     * @param file The GeoPackage location
     */
    public static GeoPackage getGeoPackage(File file) throws IOException {
        SQLiteConfig config = new SQLiteConfig();
        config.setSharedCache(true);
        config.setJournalMode(SQLiteConfig.JournalMode.OFF);
        config.setPragma(SQLiteConfig.Pragma.SYNCHRONOUS, "OFF");
        config.setLockingMode(SQLiteConfig.LockingMode.EXCLUSIVE);
        Map<String, Object> params = new HashMap<>();
        params.put(JDBCDataStoreFactory.BATCH_INSERT_SIZE.key, 10000);
        return new GeoPackage(file, config, params);
    }

}
