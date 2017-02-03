package org.jboss.security.fips.plugins;

import java.io.Serializable;

/**
 * Simple holder class for vault entries
 */
class VaultEntry implements Serializable {

	/**
	 * Do not change this suid, it is used for handling different versions of
	 * serialized data.
	 */
	private static final long serialVersionUID = 1L;

	private byte[] iv;
	private byte[] encryptedData;

	/**
	 * constructor for an entry
	 * 
	 * @param iv
	 *            initialization vector for encrypt/decrypt
	 * @param encryptedData
	 *            the encrypted password information
	 */
	VaultEntry(byte[] iv, byte[] encryptedData) {
		this.iv = iv;
		this.encryptedData = encryptedData;
	}

	/**
	 * @return the iv
	 */
	byte[] getIv() {
		return iv;
	}

	/**
	 * @return the encryptedData
	 */
	byte[] getEncryptedData() {
		return encryptedData;
	}
}