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
/*
 * This is adapted from the implementation of:
 *
 *     org.picketbox.plugins.vault.PicketBoxSecurityVault
 *
 * The full header for that file is included above.
 */
package org.jboss.security.fips.plugins;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.jboss.logging.Logger;
import org.jboss.security.fips.utils.FIPSCryptoUtil;
import org.jboss.security.fips.utils.FIPSVaultFileUtil;
import org.jboss.security.fips.utils.FIPSVaultOptions;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

/**
 * An instance of {@link SecurityVault} that uses the Mozilla Network Security
 * Services for Java (JSS) Java Cryptography Architecture (JCA) provider to mask
 * passwords using FIPS 140-2 compliant cryptography.
 * 
 * The following system property is expected to be defined in the Red Hat JBoss
 * Enterprise Application Platform (EAP) configuration file:
 * <ul>
 * <li>fips.vault.path: fully-qualified path to the Mozilla NSS database
 * directory</li>
 * </ul>
 * The following options are expected in the {@link SecurityVault#init(Map)}
 * call:
 * <ul>
 * <li>TOKEN_PIN: Masked NSS cryptographic token PIN. Has to be prepended with
 * the literal 'MASK-' followed by a base-64 encoded value</li>
 * <li>SALT: salt of the masked token PIN. This should be a randomly generated
 * 128 bit long value encoded using base-64</li>
 * <li>IV: initialization vector used to mask the token PIN. This should be a 64
 * bit long value encoded using base-64.</li>
 * </ul>
 * 
 * @author Rich Lucente
 * @since Sep 20, 2014
 */
public class FIPSCompliantVault implements SecurityVault {

	private static final Logger LOGGER = Logger
			.getLogger(FIPSCompliantVault.class);

	// admin key constants
	public static final String ADMIN_KEY_VAULTBLOCK = "admin";
	public static final String ADMIN_KEY_ATTRIBUTE = "key";

	// property for directory containing the Mozilla NSS database files
	public static final String NSSDB_PATH_PROPERTY_NAME = "fips.vault.path";

	/*
	 * Static initializer to enable the Mozilla-JSS JCA provider and load the
	 * small native library to expose the Mozilla NSS PBKDF2 function. This
	 * class needs to be placed within a module in EAP so that it's loaded once
	 * by the modular class loader.
	 */
	static {
		String nssdbPath = System.getProperty(NSSDB_PATH_PROPERTY_NAME);

		try {
			CryptoManager.initialize(nssdbPath);
		} catch (Throwable t) {
			LOGGER.fatal("Unable to initialize the Mozilla JCA provider.  "
					+ "Please verify that the system property '"
					+ NSSDB_PATH_PROPERTY_NAME
					+ "' is defined and that the Mozilla "
					+ "NSS database files exist in that directory and "
					+ "they are initialized.");
			throw new RuntimeException(t);
		}
	}

	// key used to decrypt the vault content
	private SecretKey adminKey = null;

	// get JCA providers by name regardless of the preferred JVM order
	private Provider fipsProvider = Security.getProvider(FIPSCryptoUtil.FIPS_PROVIDER_NAME);
	private Provider nonFipsProvider = Security.getProvider(FIPSCryptoUtil.NONFIPS_PROVIDER_NAME);

	// the cryptographic token
	private CryptoToken fipsToken;

	// pseudo-random number generator
	private SecureRandom random;

	// the vault data
	private FIPSCompliantVaultData vaultContent = null;
	private boolean finishedInit = false;

	// utility to read/write vault file
	private FIPSVaultFileUtil fileUtil = new FIPSVaultFileUtil();

	// utility to process vault-options
	private FIPSVaultOptions optionsUtil = new FIPSVaultOptions();

	/**
	 * @see org.jboss.security.vault.SecurityVault#exists(String, String)
	 */
	public boolean exists(String vaultBlock, String attributeName)
			throws SecurityVaultException {
		return vaultContent.getVaultData(vaultBlock, attributeName) != null;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#handshake(java.util.Map)
	 */
	public byte[] handshake(Map<String, Object> handshakeOptions)
			throws SecurityVaultException {
		// doesn't do anything meaningful in this implementation
		return new byte[FIPSCryptoUtil.PBE_SALT_MIN_LEN];
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#init(java.util.Map)
	 */
	public void init(Map<String, Object> options) throws SecurityVaultException {
		try {
			optionsUtil.validateVaultOptions(options);
		} catch (IllegalArgumentException iae) {
			logErrorAndThrowSVE("options not valid", iae);
		}

		Password tokenPin = null;
		SecretKey maskKey = null;
		try {
			// derive the key to unmask the token PIN
			maskKey = FIPSCryptoUtil
					.nonFipsDeriveMaskKey(optionsUtil.getSalt());

			// log into the cryptographic token
			tokenPin = FIPSCryptoUtil.unmaskTokenPin(
					optionsUtil.getMaskedTokenPin(), maskKey,
					optionsUtil.getIv(), nonFipsProvider);
			fipsToken = CryptoManager.getInstance()
					.getInternalKeyStorageToken();
			fipsToken.login(tokenPin);

			// at this point, FIPS-compliant cryptography ONLY!
			nonFipsProvider = null;
		} catch (Exception e) {
			logErrorAndThrowSVE("failed to log into cryptographic token", e);
		}

		/*
		 * Because of the chicken and egg problem, we have to use the SunJCE
		 * provider first to unmask the token PIN since FIPS compliant
		 * cryptography isn't enabled until you log into the token. Now we redo
		 * unmasking the token pin using FIPS compliant cryptography only
		 */
		try {
			maskKey = FIPSCryptoUtil.fipsDeriveMaskKey(fipsToken,
					optionsUtil.getSalt());
			Password fipsTokenPin = FIPSCryptoUtil.unmaskTokenPin(
					optionsUtil.getMaskedTokenPin(), maskKey,
					optionsUtil.getIv(), fipsProvider);

			// logout so we can then login using the fips unmasked token pin
			fipsToken.logout();

			// make sure we get the same result, validating what we did with
			// SunJCE
			if (!fipsTokenPin.equals(tokenPin))
				logErrorAndThrowSVE("unmasked token PIN using FIPS provider"
						+ " does not match token PIN using SunJCE provider");

			// clear the prior pin and login again
			tokenPin.clear();
			tokenPin = fipsTokenPin;
			fipsToken.login(tokenPin);

			// set the random source
			random = SecureRandom.getInstance(FIPSCryptoUtil.PRNG_ALGORITHM,
					fipsProvider);
		} catch (Exception e) {
			logErrorAndThrowSVE(
					"failed to log into cryptographic token using FIPS derived key",
					e);
		}

		// clear the token pin since we don't need it anymore
		tokenPin.clear();

		// read raw vault content
		vaultContent = fileUtil.readVaultContent();

		// unwrap the admin key
		byte[] wrappedKey = vaultContent.getVaultData(ADMIN_KEY_VAULTBLOCK,
				ADMIN_KEY_ATTRIBUTE);

		adminKey = FIPSCryptoUtil.unwrapKey(fipsToken, wrappedKey);
		if (adminKey == null) {
			logErrorAndThrowSVE("failed to get admin key from vault");
		}

		LOGGER.info("FIPS compliant password vault successfully initialized");

		finishedInit = true;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#isInitialized()
	 */
	public boolean isInitialized() {
		return finishedInit;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#keyList()
	 */
	public Set<String> keyList() throws SecurityVaultException {
		return vaultContent.getVaultDataKeys();
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#remove(java.lang.String,
	 * java.lang.String, byte[])
	 */
	public boolean remove(String vaultBlock, String attributeName,
			byte[] sharedKey) throws SecurityVaultException {
		try {
			vaultContent.deleteVaultData(vaultBlock, attributeName);
		} catch (Exception e) {
			return false;
		}
		return true;
	}
	
	/*
	 * @see org.jboss.security.vault.SecurityVault#retrieve(java.lang.String,
	 * java.lang.String, byte[])
	 */
	public char[] retrieve(String vaultBlock, String attributeName,
			byte[] sharedKey) throws SecurityVaultException {
		// make sure map key is valid
		if (vaultBlock == null || vaultBlock.isEmpty())
			logErrorAndThrowSVE("vault block parameter is null or empty");

		if (attributeName == null || attributeName.isEmpty())
			logErrorAndThrowSVE("attribute name parameter is null or empty");

		char[] vaultValue = new char[0];

		// read the raw byte array value matching the given key
		byte[] rawBytes = vaultContent.getVaultData(vaultBlock, attributeName);

		if (rawBytes != null) {
			ByteBuffer rawBuffer = ByteBuffer.wrap(rawBytes);

			// extract the initialization vector
			byte[] iv = new byte[FIPSCryptoUtil.AES_KEY_LEN];
			rawBuffer.get(iv);

			// extract the cipher text
			byte[] ciphertext = new byte[rawBuffer.remaining()];
			rawBuffer.get(ciphertext);

			// decrypt the vault value using the admin key
			byte[] plaintext = null;
			try {
				plaintext = FIPSCryptoUtil.doCrypto(Cipher.DECRYPT_MODE,
						FIPSCryptoUtil.VAULT_CRYPTO_FULL_ALG, adminKey, iv, ciphertext,
						fipsProvider);
			} catch (Exception e) {
				logErrorAndThrowSVE("unable to decrypt vault value for '"
						+ vaultBlock
						+ FIPSCompliantVaultData.PROPERTY_SEPARATOR
						+ attributeName + "'");
			}

			// convert the plain text
			if (plaintext != null) {
				vaultValue = Charset.forName("UTF-8")
						.decode(ByteBuffer.wrap(plaintext)).array();

				// clear the plain text data
				Password.wipeBytes(plaintext);
			}
		}

		return vaultValue;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#store(java.lang.String,
	 * java.lang.String, char[], byte[])
	 * 
	 * @param sharedKey is ignored for this implementation
	 */
	public void store(String vaultBlock, String attributeName,
			char[] attributeValue, byte[] sharedKey)
			throws SecurityVaultException {
		if (vaultBlock == null || vaultBlock.isEmpty()) {
			logErrorAndThrowSVE("vault block '" + vaultBlock + "' is not valid");
		}

		if (attributeName == null || attributeName.isEmpty()) {
			logErrorAndThrowSVE("attribute name '" + attributeName
					+ "' is not valid");
		}

		// generate a random initialization vector
		byte[] iv = new byte[FIPSCryptoUtil.AES_KEY_LEN];
		random.nextBytes(iv);

		// encrypt the given attribute value using the admin key
		byte[] plaintext = Charset.forName("UTF-8")
				.encode(CharBuffer.wrap(attributeValue)).array();

		byte[] ciphertext = new byte[0];
		try {
			ciphertext = FIPSCryptoUtil.doCrypto(Cipher.ENCRYPT_MODE,
					FIPSCryptoUtil.VAULT_CRYPTO_FULL_ALG, adminKey, iv, plaintext,
					fipsProvider);
		} catch (Exception e) {
			logErrorAndThrowSVE("unable to encrypt vault entry", e);
		}

		Password.wipeChars(attributeValue);
		Password.wipeBytes(plaintext);

		// concatenate the iv and ciphertext and then store as byte array
		// in the vault
		ByteBuffer rawBuffer = ByteBuffer.wrap(new byte[iv.length
				+ ciphertext.length]);
		rawBuffer.put(iv);
		rawBuffer.put(ciphertext);

		vaultContent.addVaultData(vaultBlock, attributeName, rawBuffer.array());

		try {
			fileUtil.writeVaultData(vaultContent);
		} catch (IOException e) {
			logErrorAndThrowSVE("unable to write the vault data", e);
		}
	}

	/**
	 * @param msg
	 * @throws SecurityVaultException
	 */
	private void logErrorAndThrowSVE(String msg) throws SecurityVaultException {
		LOGGER.error(msg);
		throw new SecurityVaultException(msg);
	}

	/**
	 * @param msg
	 * @param t
	 * @throws SecurityVaultException
	 */
	private void logErrorAndThrowSVE(String msg, Throwable t)
			throws SecurityVaultException {
		LOGGER.error(msg, t);
		throw new SecurityVaultException(msg, t);
	}
}
