package org.jboss.security.fips.plugins;

/**
 * Simple holder class for vault entries
 */
class VaultEntry {
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