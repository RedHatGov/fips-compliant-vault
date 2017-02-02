/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.crypto.SecretKey;

import org.jboss.security.fips.FIPSVaultMessages;

/**
 * Utility to handle Keystore
 * 
 * @author Anil.Saldhana@redhat.com
 * @author Peter Skopek (pskopek_at_redhat_dot_com)
 * @author Rich Lucente (rlucente_at_redhat_dot_com)
 * @since Jan 12, 2009
 */
public class KeyStoreUtil {
	private static final String KEYSTORE_TYPE = "BCFKS";

	/**
	 * Get the KeyStore
	 * 
	 * @param keyStoreFile
	 *            the keystore file
	 * @param storePass
	 *            password for keystore
	 * @return the keystore
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static KeyStore getKeyStore(File keyStoreFile, char[] storePass)
			throws GeneralSecurityException, IOException {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(keyStoreFile);
			return getKeyStore(fis, storePass);
		} finally {
			safeClose(fis);
		}
	}

	/**
	 * Get the Keystore given the url to the keystore file as a string
	 * 
	 * @param fileURL
	 *            URL for the keystore file
	 * @param storePass
	 *            password for keystore
	 * @return the keystore
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static KeyStore getKeyStore(String fileURL, char[] storePass) throws GeneralSecurityException, IOException {
		if (fileURL == null)
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("fileURL");

		File file = new File(fileURL);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			return getKeyStore(fis, storePass);
		} finally {
			safeClose(fis);
		}
	}

	/**
	 * Get the Keystore given the URL to the keystore
	 * 
	 * @param url
	 *            URL for the keystore file
	 * @param storePass
	 *            password for keystore
	 * @return the keystore
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static KeyStore getKeyStore(URL url, char[] storePass) throws GeneralSecurityException, IOException {
		if (url == null)
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("url");

		InputStream is = null;
		try {
			is = url.openStream();
			return getKeyStore(is, storePass);
		} finally {
			safeClose(is);
		}
	}

	/**
	 * Get the Key Store <b>Note:</b> This method wants the InputStream to be
	 * not null.
	 * 
	 * @param ksStream
	 *            input stream for the keystore
	 * @param storePass
	 *            password for keystore
	 * @return the keystore
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws IllegalArgumentException
	 *             if ksStream is null
	 */
	public static KeyStore getKeyStore(InputStream ksStream, char[] storePass)
			throws GeneralSecurityException, IOException {
		if (ksStream == null)
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("ksStream");
		KeyStore ks = KeyStore.getInstance(CryptoUtil.PROVIDER_NAME, KEYSTORE_TYPE);
		ks.load(ksStream, storePass);
		return ks;
	}

	/**
	 * Add a secret key to the KeyStore
	 * 
	 * @param keystoreFile
	 *            the file descriptor for the keystore
	 * @param storePass
	 *            the keystore password, also used as the key password
	 * @param alias
	 *            the alias for the secret key
	 * @param key
	 *            the secret key
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static void addSecretKey(File keystoreFile, char[] storePass, String alias, SecretKey key)
			throws GeneralSecurityException, IOException {
		KeyStore keystore = getKeyStore(keystoreFile, storePass);

		// Add the secret key
		keystore.setKeyEntry(alias, key, storePass, null);

		// Save the new keystore contents
		FileOutputStream out = null;
		try {
			out = new FileOutputStream(keystoreFile);
			keystore.store(out, storePass);
			out.close();
		} finally {
			safeClose(out);
		}
	}

	/**
	 * Create new empty keystore with the given password
	 * 
	 * @param storePass
	 *            key store password
	 * @return the keystore
	 * @throws Exception
	 */
	public static KeyStore createKeyStore(char[] storePass) throws Exception {
		KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE, CryptoUtil.PROVIDER_NAME);
		ks.load(null, storePass);
		return ks;
	}

	private static void safeClose(InputStream fis) {
		try {
			if (fis != null) {
				fis.close();
			}
		} catch (Exception e) {
		}
	}

	private static void safeClose(OutputStream os) {
		try {
			if (os != null) {
				os.close();
			}
		} catch (Exception e) {
		}
	}
}