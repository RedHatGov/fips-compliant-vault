/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
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

package org.jboss.security.fips.tools;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import org.bouncycastle.util.encoders.Base64;
import org.jboss.security.fips.plugins.FIPSSecurityVault;
import org.jboss.security.fips.utils.CryptoUtil;
import org.jboss.security.fips.utils.Util;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.jboss.security.vault.SecurityVaultFactory;

/**
 * Non-interactive session for {@link VaultTool}
 *
 * @author Peter Skopek
 *
 */
public final class VaultSession {
	static final Charset CHARSET = Charset.forName("UTF-8");

	private String keystoreURL;
	private String keystorePassword;
	private String keystoreMaskedPassword;
	private String encryptionDirectory;
	private byte[] salt;
	private int iterationCount;
	private byte[] iv;
	private boolean createKeystore;

	private SecurityVault vault;
	private String vaultAlias;

	/**
	 * Constructor to create VaultSession with possibility to create keystore
	 * automatically.
	 *
	 * @param keystoreURL
	 * @param keystorePassword
	 * @param encryptionDirectory
	 * @param salt
	 * @param iterationCount
	 * @param createKeystore
	 * @throws Exception
	 */
	public VaultSession(String keystoreURL, String keystorePassword, String encryptionDirectory, byte[] salt,
			int iterationCount, byte[] iv, boolean createKeystore) throws Exception {
		this.keystoreURL = keystoreURL;
		this.keystorePassword = keystorePassword;
		this.encryptionDirectory = encryptionDirectory;
		this.salt = salt;
		this.iterationCount = iterationCount;
		this.iv = iv;
		this.createKeystore = createKeystore;
		validate();
	}

	/**
	 * Validate fields sent to this class's constructor.
	 */
	private void validate() throws Exception {
		validateEncryptionDirectory();
		validateKeystoreURL();
		validateSalt();
		validateIterationCount();
		validateIv();
		validateKeystorePassword();
	}

	protected void validateKeystoreURL() throws Exception {
		File f = new File(keystoreURL);
		if (!f.exists()) {
			if (createKeystore) {
				f.getParentFile().mkdirs();
				if (f.createNewFile()) {
					f.delete();
				} else {
					throw new Exception("Keystore [" + keystoreURL + "] cannot be created.");
				}
			} else {
				throw new Exception("Keystore [" + keystoreURL + "] doesn't exist.");
			}
		} else if (!f.canWrite() || !f.isFile()) {
			throw new Exception("Keystore [" + keystoreURL + "] is not writable or not a file.");
		}
	}

	protected void validateKeystorePassword() throws Exception {
		if (keystorePassword == null || keystorePassword.isEmpty()) {
			throw new Exception("Keystore password has to be specified.");
		}
	}

	protected void validateEncryptionDirectory() throws Exception {
		if (encryptionDirectory == null) {
			throw new Exception("Encryption directory has to be specified.");
		}
		if (!(encryptionDirectory.endsWith("/") || encryptionDirectory.endsWith("\\"))) {
			encryptionDirectory = encryptionDirectory + (System.getProperty("file.separator", "/"));
		}
		File d = new File(encryptionDirectory);
		if (!d.exists()) {
			if (!d.mkdirs()) {
				throw new Exception("Cannot create encryption directory " + d.getAbsolutePath());
			}
		}
		if (!d.isDirectory()) {
			throw new Exception(
					"Encryption directory is not a directory or doesn't exist. (" + encryptionDirectory + ")");
		}
	}

	protected void validateIterationCount() throws Exception {
		if (iterationCount < CryptoUtil.PBE_MIN_ITERATION_COUNT) {
			throw new Exception("Iteration count has to be at least " + CryptoUtil.PBE_MIN_ITERATION_COUNT + ", but is "
					+ iterationCount + ".");
		}
	}

	protected void validateSalt() throws Exception {
		if (salt == null || salt.length < CryptoUtil.PBE_SALT_MIN_LEN) {
			throw new Exception("Salt has to be at least " + CryptoUtil.PBE_SALT_MIN_LEN + " bytes long.");
		}
	}

	protected void validateIv() throws Exception {
		if (iv == null || iv.length != CryptoUtil.MASK_KEY_STRENGTH / 8) {
			throw new Exception("Initialization vector must be " + CryptoUtil.MASK_KEY_STRENGTH / 8 + " bytes long.");
		}
	}

	/**
	 * Method to compute masked password based on class attributes.
	 *
	 * @return masked password prefixed with
	 *         {link @FIPSSecurityVault.PASS_MASK_PREFIX}.
	 * @throws Exception
	 */
	private String computeMaskedPassword() throws Exception {

		// get the mask key
		SecretKey maskKey = CryptoUtil.deriveMaskKey(salt, iterationCount);
		String maskedPass = CryptoUtil.maskKeystorePassword(keystorePassword.toCharArray(), maskKey, iv);

		return FIPSSecurityVault.PASS_MASK_PREFIX + maskedPass;
	}

	/**
	 * Initialize the underlying vault.
	 *
	 * @throws Exception
	 */
	private void initSecurityVault() throws Exception {
		try {
			this.vault = SecurityVaultFactory.get(FIPSSecurityVault.class.getName());
			this.vault.init(getVaultOptionsMap());
		} catch (SecurityVaultException e) {
			throw new Exception("Exception encountered:" + e.getLocalizedMessage(), e);
		}
	}

	/**
	 * Start the vault with given alias.
	 *
	 * @throws Exception
	 */
	public void startVaultSession(String vaultAlias) throws Exception {
		if (vaultAlias == null) {
			throw new Exception("Vault alias has to be specified.");
		}
		this.keystoreMaskedPassword = (Util.isPasswordCommand(keystorePassword)) ? keystorePassword
				: computeMaskedPassword();
		this.vaultAlias = vaultAlias;
		initSecurityVault();
	}

	private Map<String, Object> getVaultOptionsMap() {
		Map<String, Object> options = new HashMap<String, Object>();
		options.put(FIPSSecurityVault.KEYSTORE_URL, keystoreURL);
		options.put(FIPSSecurityVault.KEYSTORE_PASSWORD, keystoreMaskedPassword);
		options.put(FIPSSecurityVault.KEYSTORE_ALIAS, vaultAlias);
		options.put(FIPSSecurityVault.SALT, Base64.toBase64String(salt));
		options.put(FIPSSecurityVault.ITERATION_COUNT, Integer.toString(iterationCount));
		options.put(FIPSSecurityVault.INITIALIZATION_VECTOR, Base64.toBase64String(iv));
		options.put(FIPSSecurityVault.ENC_FILE_DIR, encryptionDirectory);
		if (createKeystore) {
			options.put(FIPSSecurityVault.CREATE_KEYSTORE, Boolean.toString(createKeystore));
		}
		return options;
	}

	/**
	 * Add secured attribute to specified vault block. This method can be called
	 * only after successful startVaultSession() call.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 * @param attributeValue
	 * @return secured attribute configuration
	 */
	public String addSecuredAttribute(String vaultBlock, String attributeName, char[] attributeValue) throws Exception {
		vault.store(vaultBlock, attributeName, attributeValue, null);
		return securedAttributeConfigurationString(vaultBlock, attributeName);
	}

	/**
	 * Add secured attribute to specified vault block. This method can be called
	 * only after successful startVaultSession() call. After successful storage
	 * the secured attribute information will be displayed at standard output.
	 * For silent method @see addSecuredAttribute
	 *
	 * @param vaultBlock
	 * @param attributeName
	 * @param attributeValue
	 * @throws Exception
	 */
	public void addSecuredAttributeWithDisplay(String vaultBlock, String attributeName, char[] attributeValue)
			throws Exception {
		vault.store(vaultBlock, attributeName, attributeValue, null);
		attributeCreatedDisplay(vaultBlock, attributeName);
	}

	/**
	 * Check whether secured attribute is already set for given vault block and
	 * attribute name. This method can be called only after successful
	 * startVaultSession() call.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 * @return true is password already exists for given vault block and
	 *         attribute name.
	 * @throws Exception
	 */
	public boolean checkSecuredAttribute(String vaultBlock, String attributeName) throws Exception {
		return vault.exists(vaultBlock, attributeName);
	}

	/**
	 * This method removes secured attribute stored in {@link SecurityVault}.
	 * After successful remove operation returns true. Otherwise false.
	 *
	 * @param vaultBlock
	 *            security vault block
	 * @param attributeName
	 *            Attribute name stored in security vault
	 * @return true is operation is successful, otherwise false
	 * @throws Exception
	 */
	public boolean removeSecuredAttribute(String vaultBlock, String attributeName) throws Exception {
		return vault.remove(vaultBlock, attributeName, null);
	}

	/**
	 * Retrieves secured attribute from specified vault block with specified
	 * attribute name. This method can be called only after successful
	 * startVaultSession() call.
	 *
	 * @param vaultBlock
	 *            security vault block
	 * @param attributeName
	 *            Attribute name stored in security vault
	 * @return value of secured attribute if exists, otherwise null
	 * @throws Exception
	 */
	public char[] retrieveSecuredAttribute(String vaultBlock, String attributeName) throws Exception {
		return vault.retrieve(vaultBlock, attributeName, null);
	}

	/**
	 * Display info about stored secured attribute.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 */
	private void attributeCreatedDisplay(String vaultBlock, String attributeName) {
		System.out.println();
		System.out.println("********************************************");
		System.out.println("Secured attribute value has been stored in vault.");
		System.out.println("Please make note of the following:");
		System.out.println("********************************************");
		System.out.println("Vault Block:" + vaultBlock);
		System.out.println("Attribute Name:" + attributeName);
		System.out.println();
		System.out.println("The following string should be cut/pasted wherever this password occurs in the");
		System.out.println("EAP configuration file.  If you're changing an existing password in the vault,");
		System.out.println("the entry in the configuration file can remain the same:");
		System.out.println("${" + securedAttributeConfigurationString(vaultBlock, attributeName) + "}");
		System.out.println("********************************************");
	}

	/**
	 * Returns configuration string for secured attribute.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 * @return
	 */
	private String securedAttributeConfigurationString(String vaultBlock, String attributeName) {
		return "VAULT::" + vaultBlock + "::" + attributeName + "::1";
	}

	/**
	 * Display info about vault itself in form of AS7 configuration file.
	 */
	public void vaultConfigurationDisplay() {
		System.out.println();
		System.out.println("********************************************");
		System.out.println("Vault Configuration in configuration file:");
		System.out.println("********************************************");
		System.out.println("    ...");
		System.out.println("    </extensions>");
		System.out.println(vaultConfiguration());
		System.out.println("    <management>");
		System.out.println("    ...");
		System.out.println("********************************************");
	}

	/**
	 * Returns vault configuration string in user readable form.
	 * 
	 * @return
	 */
	public String vaultConfiguration() {
		StringBuilder sb = new StringBuilder();
		sb.append("    <vault code=\"" + FIPSSecurityVault.class.getName() + "\" module=\"org.jboss.security.fips\" >")
				.append("\n");

		createKeystore = false;
		Map<String, Object> vaultOptions = getVaultOptionsMap();

		List<String> keys = new ArrayList<String>(vaultOptions.keySet());
		Collections.sort(keys);

		for (String key : keys) {
			sb.append("      <vault-option name=\"" + key + "\" value=\"" + vaultOptions.get(key) + "\"/>")
					.append("\n");
		}

		sb.append("    </vault>");
		return sb.toString();
	}

	/**
	 * Method to get keystore masked password to use further in configuration.
	 * Has to be used after {@link startVaultSession} method.
	 *
	 * @return the keystoreMaskedPassword
	 */
	public String getKeystoreMaskedPassword() {
		return keystoreMaskedPassword;
	}

	/**
	 * Display format for couple of vault block and attribute name.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 * @return formatted {@link String}
	 */
	static String blockAttributeDisplayFormat(String vaultBlock, String attributeName) {
		return "[" + vaultBlock + "::" + attributeName + "]";
	}
}
