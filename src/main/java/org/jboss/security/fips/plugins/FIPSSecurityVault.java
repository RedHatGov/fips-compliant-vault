/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.fips.plugins;

import org.bouncycastle.util.encoders.Base64;
import org.jboss.security.fips.FIPSVaultMessages;
import org.jboss.security.fips.FIPSLogger;
import org.jboss.security.fips.utils.CryptoUtil;
import org.jboss.security.fips.utils.KeyStoreUtil;
import org.jboss.security.fips.utils.StringUtil;
import org.jboss.security.fips.utils.Util;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;

import javax.crypto.SecretKey;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.KeyStore.Entry;
import java.util.Map;
import java.util.Set;

/**
 * An instance of {@link SecurityVault} that uses a {@link KeyStore}. The shared
 * key is not used by this implementation.
 * 
 * The following options are expected in the {@link SecurityVault#init(Map)}
 * call:
 * <ul>
 * <li>ENC_FILE_DIR: the location where the encoded files will be kept. End with
 * "/" or "\" based on your platform</li>
 * <li>KEYSTORE_URL: location where your keystore is located</li>
 * <li>KEYSTORE_PASSWORD: keystore password. This can be retrieved in a number
 * of ways, enumerated below.</li>
 * <ul>
 * <li>the masked password as a base64 string prepended with the literal
 * 'MASK-'</li>
 * <li>the literal '{EXT}...' where the '...' is the exact command line that
 * will be passed to the Runtime.exec(String) method to execute a platform
 * command. The first line of the command output is used as the password.</li>
 * <li>the literal '{EXTC[:expiration_in_millis]}...' where the '...' is the
 * exact command line that will be passed to the Runtime.exec(String) method to
 * execute a platform command. The first line of the command output is used as
 * the password. EXTC variant will cache the passwords for expiration_in_millis
 * milliseconds. Default cache expiration is 0 = infinity.</li>
 * <li>the literal '{CMD}...' or '{CMDC}...' for a general command to execute.
 * The general command is a string delimited by ',' where the first part is the
 * actual command and further parts represents its parameters. The comma can be
 * backslashed in order to keep it as the part of a parameter.</li>
 * <li>the literal '{CLASS[@modulename]}classname[:ctorargs]' where the
 * '[:ctorargs]' is an optional string delimited by the ':' from the classname
 * that will be passed to the classname ctor. The ctorargs itself is a comma
 * delimited list of strings. The password is obtained from classname by
 * invoking a 'char[] toCharArray()' method if found, otherwise, the 'String
 * toString()'</li>
 * </ul>
 * <li>KEYSTORE_ALIAS: Alias where the AES-128 administrative key is located
 * within the keystore.</li>
 * <li>SALT: salt of the masked password as a base-64 encoded string. This
 * should be at least 128 bits in length before base-64 encoding per NIST SP
 * 800-132 PBKDF2 recommendations.</li>
 * <li>INITIALIZATION_VECTOR: the iv to use to unmask the encrypted password per
 * the 'MASK-' option for KEYSTORE_PASSWORD. This must be 16 bytes in length per
 * AES-128 requirements.</li>
 * <li>ITERATION_COUNT: Iteration Count of the masked password. This must be at
 * least 1000 per NIST SP 800-132 PBKDF2 recommendations.</li>
 * <li>CREATE_KEYSTORE: Whether PicketBox Security Vault has to create missing
 * key store in time of initialization. Default is "FALSE".</li>
 * </ul>
 * 
 * @author Anil.Saldhana@redhat.com
 * @author Peter Skopek (pskopek_at_redhat_dot_com)
 * @author Rich Lucente (rlucente_at_redhat_dot_com)
 * @since Aug 12, 2011
 */
public class FIPSSecurityVault implements SecurityVault {
	protected boolean finishedInit = false;

	protected KeyStore keystore = null;

	private char[] storePass = null;

	private String alias = null;

	private SecurityVaultData vaultContent = null;

	private SecretKey adminKey;

	private String vaultDataPath;

	private boolean createKeyStore = false;

	// options
	public static final String ENC_FILE_DIR = "ENC_FILE_DIR";

	public static final String KEYSTORE_URL = "KEYSTORE_URL";

	public static final String KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";

	public static final String KEYSTORE_ALIAS = "KEYSTORE_ALIAS";

	public static final String SALT = "SALT";

	public static final String INITIALIZATION_VECTOR = "INITIALIZATION_VECTOR";

	public static final String ITERATION_COUNT = "ITERATION_COUNT";

	public static final String PASS_MASK_PREFIX = "MASK-";

	public static final String CREATE_KEYSTORE = "CREATE_KEYSTORE";

	// file holding all of the vault entries
	protected static final String VAULT_CONTENT_FILE = "vault.dat";

	/*
	 * @see org.jboss.security.vault.SecurityVault#init(java.util.Map)
	 */
	public void init(Map<String, Object> options) throws SecurityVaultException {
		if (options == null || options.isEmpty())
			throw FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMap("options");

		String keystoreURL = (String) options.get(KEYSTORE_URL);
		if (keystoreURL == null)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(KEYSTORE_URL));

		if (keystoreURL.contains("${")) {
			keystoreURL = keystoreURL.replaceAll(":", StringUtil.PROPERTY_DEFAULT_SEPARATOR); // replace
																								// single
																								// ":"
																								// with
																								// PL
																								// default
		}
		keystoreURL = StringUtil.getSystemPropertyAsString(keystoreURL);

		String password = (String) options.get(KEYSTORE_PASSWORD);
		if (password == null)
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(KEYSTORE_PASSWORD));
		if (password.startsWith(PASS_MASK_PREFIX) == false && Util.isPasswordCommand(password) == false)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.invalidKeystorePasswordFormatMessage());

		String saltStr = (String) options.get(SALT);
		if (saltStr == null)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(SALT));

		byte[] salt = Base64.decode(saltStr);
		if (salt.length < CryptoUtil.PBE_SALT_MIN_LEN)
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.saltTooShortMessage(SALT, CryptoUtil.PBE_SALT_MIN_LEN));

		String ivStr = (String) options.get(INITIALIZATION_VECTOR);
		if (ivStr == null)
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(INITIALIZATION_VECTOR));
		byte[] iv = Base64.decode(ivStr);
		if (iv.length != CryptoUtil.KEY_STRENGTH / 8)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES
					.ivLengthDoesNotMatchBlockSizeMessage(INITIALIZATION_VECTOR, CryptoUtil.KEY_STRENGTH));

		CryptoUtil.setDefaultDrbg(saltStr, ivStr);
		
		String iterationCountStr = (String) options.get(ITERATION_COUNT);
		if (iterationCountStr == null)
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(ITERATION_COUNT));
		int iterationCount = Integer.parseInt(iterationCountStr);
		if (iterationCount < CryptoUtil.PBE_MIN_ITERATION_COUNT)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.iterationCountTooLowMessage(ITERATION_COUNT,
					CryptoUtil.PBE_MIN_ITERATION_COUNT));

		this.alias = (String) options.get(KEYSTORE_ALIAS);
		if (alias == null)
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(KEYSTORE_ALIAS));

		String encFileDir = (String) options.get(ENC_FILE_DIR);
		if (encFileDir == null)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.invalidNullOrEmptyOptionMessage(ENC_FILE_DIR));
		vaultDataPath = determineVaultDataPath(encFileDir);

		createKeyStore = (options.get(CREATE_KEYSTORE) != null
				? Boolean.parseBoolean((String) options.get(CREATE_KEYSTORE)) : false);

		try {
			storePass = loadKeystorePassword(password, salt, iterationCount, iv);
			keystore = getKeyStore(keystoreURL);
		} catch (Exception e) {
			throw new SecurityVaultException(e);
		}

		// read vault content
		readVaultContent(keystoreURL);

		FIPSLogger.LOGGER.infoVaultInitialized();
		finishedInit = true;

	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#isInitialized()
	 */
	public boolean isInitialized() {
		return finishedInit;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#handshake(java.util.Map)
	 */
	public byte[] handshake(Map<String, Object> handshakeOptions) throws SecurityVaultException {
		return new byte[CryptoUtil.KEY_STRENGTH];
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#keyList()
	 */
	public Set<String> keyList() throws SecurityVaultException {
		return vaultContent.getVaultDataKeys();
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#store(java.lang.String,
	 * java.lang.String, char[], byte[])
	 */
	public void store(String vaultBlock, String attributeName, char[] attributeValue, byte[] sharedKey)
			throws SecurityVaultException {
		if (StringUtil.isNullOrEmpty(vaultBlock))
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("vaultBlock");
		if (StringUtil.isNullOrEmpty(attributeName))
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("attributeName");

		try {
			// generate the initialization vector
			byte[] iv = CryptoUtil.genRandomBytes(CryptoUtil.KEY_STRENGTH / 8);

			// encrypt the value
			byte[] ciphertext = CryptoUtil.encrypt(adminKey, iv, attributeValue);

			// store the value
			vaultContent.addVaultData(vaultBlock, attributeName, new VaultEntry(iv, ciphertext));
		} catch (Exception e1) {
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.unableToEncryptDataMessage(), e1);
		}

		try {
			writeVaultData();
		} catch (IOException e) {
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.unableToWriteVaultDataFileMessage(vaultDataPath), e);
		}
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#retrieve(java.lang.String,
	 * java.lang.String, byte[])
	 */
	public char[] retrieve(String vaultBlock, String attributeName, byte[] sharedKey) throws SecurityVaultException {
		if (StringUtil.isNullOrEmpty(vaultBlock))
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("vaultBlock");
		if (StringUtil.isNullOrEmpty(attributeName))
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("attributeName");

		VaultEntry vaultEntry = vaultContent.getVaultData(vaultBlock, attributeName);

		try {
			if (vaultEntry == null)
				throw new SecurityVaultException(
						FIPSVaultMessages.MESSAGES.unableToGetPasswordFromVault(vaultBlock, attributeName));

			return CryptoUtil.decrypt(adminKey, vaultEntry.getIv(), vaultEntry.getEncryptedData());
		} catch (Exception e) {
			throw new SecurityVaultException(e);
		}
	}

	/**
	 * @see org.jboss.security.vault.SecurityVault#exists(String, String)
	 */
	public boolean exists(String vaultBlock, String attributeName) throws SecurityVaultException {
		return vaultContent.getVaultData(vaultBlock, attributeName) != null;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#remove(java.lang.String,
	 * java.lang.String, byte[])
	 */
	public boolean remove(String vaultBlock, String attributeName, byte[] sharedKey) throws SecurityVaultException {
		if (StringUtil.isNullOrEmpty(vaultBlock))
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("vaultBlock");
		if (StringUtil.isNullOrEmpty(attributeName))
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("attributeName");

		try {
			if (vaultContent.deleteVaultData(vaultBlock, attributeName)) {
				writeVaultData();
				return true;
			}
			return false;
		} catch (IOException e) {
			throw new SecurityVaultException(
					FIPSVaultMessages.MESSAGES.unableToWriteVaultDataFileMessage(VAULT_CONTENT_FILE), e);
		} catch (Exception e) {
			throw new SecurityVaultException(e);
		}
	}

	/**
	 * Determine the path to the directory for the vault data file. This will
	 * substitute any properties that are embedded within the directory name.
	 * 
	 * @param vaultDir
	 *            the initial vault directory with possible embedded properties
	 * @return the path to the vault data file
	 * @throws SecurityVaultException
	 */
	private String determineVaultDataPath(String vaultDir) throws SecurityVaultException {
		// determine if there are properties embedded in the file directory
		if (vaultDir.contains("${)")) {
			// replace single ':' with PL default property separator
			vaultDir = vaultDir.replaceAll(":", StringUtil.PROPERTY_DEFAULT_SEPARATOR);

			// decode any embedded property values
			vaultDir = StringUtil.getSystemPropertyAsString(vaultDir);
		}

		FIPSLogger.LOGGER.traceDecodedVaultDirectory(vaultDir);

		// make sure that decoded value ends with file separator
		if (!vaultDir.endsWith(File.separator))
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.invalidDirectoryFormatMessage(vaultDir));

		if (directoryExists(vaultDir) == false)
			throw new SecurityVaultException(FIPSVaultMessages.MESSAGES.fileOrDirectoryDoesNotExistMessage(vaultDir));

		return vaultDir + VAULT_CONTENT_FILE;
	}

	/**
	 * Load the keystore password from multiple options based on the given
	 * definition including unmasking the string, running a platform command, or
	 * using a custom class
	 * 
	 * @param passwordDef
	 *            how the password should be retrieved, typically an obfuscated
	 *            string
	 * @param salt
	 *            the salt for PBKDF2
	 * @param iterationCount
	 *            the iteration count for PBKDF2
	 * @param iv
	 *            once a key is derived, the initialization vector used to
	 *            decrypt
	 * @return the keystore password as a character array
	 * @throws Exception
	 */
	private char[] loadKeystorePassword(String passwordDef, byte[] salt, int iterationCount, byte[] iv)
			throws Exception {
		final char[] password;

		if (passwordDef.startsWith(PASS_MASK_PREFIX)) {
			SecretKey maskKey = CryptoUtil.deriveMaskKey(salt, iterationCount);
			try {
				password = CryptoUtil.unmaskKeystorePassword(passwordDef.substring(PASS_MASK_PREFIX.length()), maskKey,
						iv);
			} catch (Throwable t) {
				throw FIPSVaultMessages.MESSAGES.invalidUnmaskedKeystorePasswordMessage(t, passwordDef);
			}
		} else
			password = Util.loadPassword(passwordDef);

		return password;
	}

	/**
	 * Creates a new password vault and writes it to the filesystem. Also, gets
	 * the admin key. If one does not exist, it's created and written to the
	 * keystore
	 * 
	 * @param keystoreURL
	 *            the keystore file location
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private void setUpVault(String keystoreURL) throws IOException, GeneralSecurityException {
		vaultContent = new SecurityVaultData();
		writeVaultData();

		adminKey = getAdminKey();
		if (adminKey == null) {
			// create new key for new vault
			FIPSLogger.LOGGER.generatingNewAdminKey(alias);
			adminKey = CryptoUtil.generateKey();

			// store it under specified alias
			KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(adminKey);
			try {
				keystore.setEntry(alias, skEntry, new KeyStore.PasswordProtection(storePass));
				saveKeyStoreToFile(keystoreURL);
			} catch (KeyStoreException e) {
				throw FIPSVaultMessages.MESSAGES.noSecretKeyandAliasAlreadyUsed(alias);
			} catch (Exception e) {
				throw FIPSVaultMessages.MESSAGES.unableToStoreKeyStoreToFile(e, keystoreURL);
			}
		}
	}

	/**
	 * Write the vault data to the filesystem
	 * 
	 * @throws IOException
	 */
	private void writeVaultData() throws IOException {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream(vaultDataPath);
			oos = new ObjectOutputStream(fos);
			oos.writeObject(vaultContent);
		} finally {
			safeClose(oos);
			safeClose(fos);
		}
	}

	/**
	 * @return true if the vault data file exists and its writable and readable
	 */
	private boolean vaultFileExists() {
		File file = new File(vaultDataPath);
		return file != null && file.exists() && file.canRead() && file.canWrite();
	}

	/**
	 * @param dir
	 *            directory being tested
	 * @return true if the directory exists
	 */
	private boolean directoryExists(String dir) {
		File file = new File(dir);
		return file != null && file.exists() && file.isDirectory();
	}

	/**
	 * Silently close a resource
	 * 
	 * @param c
	 *            the resource to close
	 */
	private void safeClose(Closeable c) {
		try {
			if (c != null) {
				c.close();
			}
		} catch (Throwable t) {
		}
	}

	/**
	 * Loads existing vault content or sets up a new vault if none exists. Also
	 * sets the admin key to decrypt the vault data by either reading it from
	 * the keystore or creating it and storing it in the keystore
	 * 
	 * @param keystoreURL
	 *            the URL to the keystore
	 * @throws SecurityVaultException
	 */
	private void readVaultContent(String keystoreURL) throws SecurityVaultException {

		try {
			if (vaultFileExists()) {
				readVaultContent();
			} else {
				setUpVault(keystoreURL);
			}
		} catch (Exception e) {
			throw new SecurityVaultException(e);
		}
	}

	/**
	 * Writes the existing keystore to the given URL
	 * 
	 * @param keystoreURL
	 *            the location to write the keystore
	 * @throws Exception
	 */
	private void saveKeyStoreToFile(String keystoreURL) throws Exception {
		keystore.store(new FileOutputStream(new File(keystoreURL)), storePass);
	}

	/**
	 * Reads the vault data and sets the administrative cryptographic key to
	 * enable decrypting the password data
	 * 
	 * @throws Exception
	 */
	private void readVaultContent() throws Exception {
		FileInputStream fis = null;
		ObjectInputStream ois = null;

		try {
			fis = new FileInputStream(vaultDataPath);
			ois = new ObjectInputStream(fis);
			vaultContent = (SecurityVaultData) ois.readObject();
		} finally {
			safeClose(fis);
			safeClose(ois);
		}

		adminKey = getAdminKey();
		if (adminKey == null) {
			throw FIPSVaultMessages.MESSAGES.vaultDoesnotContainSecretKey(alias);
		}
	}

	/**
	 * Returns SecretKey stored in defined keystore under defined alias. If no
	 * such SecretKey exists returns null.
	 * 
	 * @return secret key matching alias or null if no key
	 */
	private SecretKey getAdminKey() {
		try {
			Entry e = keystore.getEntry(alias, new KeyStore.PasswordProtection(storePass));
			if (e instanceof KeyStore.SecretKeyEntry) {
				return ((KeyStore.SecretKeyEntry) e).getSecretKey();
			}
		} catch (Exception e) {
			FIPSLogger.LOGGER.vaultDoesNotContainSecretKey(alias);
			return null;
		}
		return null;
	}

	/**
	 * Get key store based on options passed to the security vault.
	 * 
	 * @return the existing keystore or a new keystore
	 */
	private KeyStore getKeyStore(String keystoreURL) {

		try {
			if (createKeyStore) {
				return KeyStoreUtil.createKeyStore(storePass);
			}
		} catch (Throwable e) {
			throw FIPSVaultMessages.MESSAGES.unableToGetKeyStore(e, keystoreURL);
		}

		try {
			return KeyStoreUtil.getKeyStore(keystoreURL, storePass);
		} catch (IOException e) {
			throw FIPSVaultMessages.MESSAGES.unableToGetKeyStore(e, keystoreURL);
		} catch (GeneralSecurityException e) {
			throw FIPSVaultMessages.MESSAGES.unableToGetKeyStore(e, keystoreURL);
		}
	}
}
