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
*     org.picketbox.plugins.vault.SecurityVaultData
*
* The full header for that file is included above.
*/
package org.jboss.security.fips.plugins;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simply store the vault data in a serialized Map using a key that concatenates
 * vaultBlock and attributeName and a value that contains the wrapped or
 * encrypted cryptographic keys and passwords.
 * 
 * @author Rich Lucente
 */
public class FIPSCompliantVaultData implements Serializable {

	// used to concatenate key strings
	static final String PROPERTY_SEPARATOR = "::";

	// UTF-8 representation of "FIPS-140" for this vault
	private static final long serialVersionUID = 0x464950532d313430L;

	// vault data mapping vault block to masked key
	private transient Map<String, byte[]> vaultData = new ConcurrentHashMap<String, byte[]>();

	/**
	 * default constructor
	 */
	public FIPSCompliantVaultData() {
	}

	/**
	 * Writes object to the ObjectOutputSteream.
	 * 
	 * @param oos
	 * @throws IOException
	 */
	private void writeObject(ObjectOutputStream oos) throws IOException {
		oos.writeObject(vaultData);
	}

	/**
	 * Reads object from the ObjectInputStream.
	 * 
	 * @param ois
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	@SuppressWarnings("unchecked")
	private void readObject(ObjectInputStream ois) throws IOException,
			ClassNotFoundException {
		this.vaultData = (Map<String, byte[]>) ois.readObject();
	}

	/**
	 * Retrieves the data stored in vault storage.
	 * 
	 * @param vaultBlock
	 * @param attributeName
	 * @return
	 */
	byte[] getVaultData(String vaultBlock, String attributeName) {
		return vaultData.get(dataKey(vaultBlock, attributeName));
	}

	/**
	 * 
	 * @param vaultBlock
	 * @param attributeName
	 * @param encryptedData
	 */
	void addVaultData(String vaultBlock, String attributeName,
			byte[] encryptedData) {
		vaultData.put(dataKey(vaultBlock, attributeName), encryptedData);
	}

	/**
	 * 
	 * @param vaultBlock
	 * @param attributeName
	 */
	void deleteVaultData(String vaultBlock, String attributeName) {
		vaultData.remove(dataKey(vaultBlock, attributeName));
	}

	/**
	 * Returns mapping keys for all stored data.
	 * 
	 * @return
	 */
	Set<String> getVaultDataKeys() {
		return vaultData.keySet();
	}

	/**
	 * Creates new format for data key in vault. All parameters have to be
	 * non-null.
	 * 
	 * @param vaultBlock
	 * @param attributeName
	 * @return concatenated key for map lookup
	 */
	private String dataKey(String vaultBlock, String attributeName) {
		return vaultBlock + PROPERTY_SEPARATOR + attributeName;
	}
}
