/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.security.fips.utils;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.jboss.logging.Logger;
import org.jboss.security.fips.plugins.FIPSCompliantVault;
import org.jboss.security.fips.plugins.FIPSCompliantVaultData;
import org.jboss.security.vault.SecurityVaultException;

/**
 * Utility functions for FIPS-compliant vault file operations
 * 
 * @author Rich Lucente
 * @since Oct 30, 2014
 */
public class FIPSVaultFileUtil {
	private static final Logger LOGGER = Logger
			.getLogger(FIPSVaultFileUtil.class);

	// vault data file
	private static final String VAULT_CONTENT_FILE = "vault.dat";

	// fully qualified path of vault directory
	private String vaultFileFullPath;

	/**
	 * Constructor for file utilities to read/write vault content
	 * 
	 * @throws SecurityVaultException
	 */
	public FIPSVaultFileUtil() {
		// set the full path for the vault file
		String vaultDir = System
				.getProperty(FIPSCompliantVault.NSSDB_PATH_PROPERTY_NAME);

		if (!vaultDir.endsWith(File.pathSeparator)) {
			vaultDir = vaultDir + File.pathSeparator;
		}

		vaultFileFullPath = vaultDir + VAULT_CONTENT_FILE;
	}

	/**
	 * Reads the raw content of the vault file.
	 * 
	 * @throws SecurityVaultException
	 *             if the vault file does not exist or is not readable
	 */
	public FIPSCompliantVaultData readVaultContent()
			throws SecurityVaultException {
		FIPSCompliantVaultData vaultContent = new FIPSCompliantVaultData();

		if (vaultFileExists() == false) {
			String msg = "The vault file does not exist or is not readable";
			LOGGER.error(msg);
			throw new SecurityVaultException(msg);
		}

		try {
			// read the vault content
			FileInputStream fis = null;
			ObjectInputStream ois = null;
			try {
				fis = new FileInputStream(vaultFileFullPath);
				ois = new ObjectInputStream(fis);
				vaultContent = (FIPSCompliantVaultData) ois.readObject();
			} finally {
				quietlyClose(fis);
				quietlyClose(ois);
			}
		} catch (Exception e) {
			throw new SecurityVaultException(e);
		}

		return vaultContent;
	}

	/**
	 * Write the vault data content to the vault file
	 * 
	 * @param vaultContent
	 *            the raw vault data
	 * @throws IOException
	 */
	public void writeVaultData(FIPSCompliantVaultData vaultContent)
			throws IOException {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream(vaultFileFullPath);
			oos = new ObjectOutputStream(fos);
			oos.writeObject(vaultContent);
		} finally {
			quietlyClose(oos);
			quietlyClose(fos);
		}
	}

	/**
	 * quietly close the stream
	 * 
	 * @param stream
	 */
	private static void quietlyClose(Closeable stream) {
		try {
			if (stream != null) {
				stream.close();
			}
		} catch (Exception e) {
		}
	}

	/**
	 * @return true if file exists and readable, false otherwise
	 */
	private boolean vaultFileExists() {
		File vaultPath = new File(vaultFileFullPath);
		return vaultPath.exists() && vaultPath.canRead();
	}
}
