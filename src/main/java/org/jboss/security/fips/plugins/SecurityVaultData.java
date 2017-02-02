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
package org.jboss.security.fips.plugins;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.security.fips.utils.StringUtil;

/**
 * Security vault data store for passwords.
 * 
 * @author Peter Skopek (pskopek_at_redhat_dot_com)
 * @author Rich Lucente (rlucente_at_redhat_dot_com)
 */
public class SecurityVaultData implements Serializable {

	/**
	 * Do not change this suid, it is used for handling different versions of
	 * serialized data.
	 */
	private static final long serialVersionUID = 1L;

	/*
	 * each key maps to a vault entry that contains an initialization vector and
	 * the encrypted data
	 */
	private transient Map<String, VaultEntry> vaultData = new ConcurrentHashMap<String, VaultEntry>();

	/**
	 * Default constructor.
	 */
	public SecurityVaultData() {
	}

	/**
	 * Writes object to the ObjectOutputStream.
	 * 
	 * @param oos
	 * @throws IOException
	 */
	private void writeObject(ObjectOutputStream oos) throws IOException {
		oos.writeObject(vaultData);
	}

	/**
	 * Reads object from the ObjectInputStream. This method needs to be changed
	 * when implementing changes in data.
	 * 
	 * @param ois
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	@SuppressWarnings("unchecked")
	private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
		this.vaultData = (Map<String, VaultEntry>) ois.readObject();
	}

	/**
	 * Retrieves the data stored in vault storage.
	 * 
	 * @param vaultBlock
	 *            the block location in the vault
	 * @param attributeName
	 *            the attribute name within the block
	 * @return a vault entry containing the iv and encrypted data
	 */
	VaultEntry getVaultData(String vaultBlock, String attributeName) {
		return vaultData.get(dataKey(vaultBlock, attributeName));
	}

	/**
	 * Add attribute's data to the vault at the given block
	 * 
	 * @param vaultBlock
	 *            the block location in the vault
	 * @param attributeName
	 *            the attribute name within the block
	 * @param entry
	 *            vault entry encapsulating the iv and encrypted attribute value
	 */
	void addVaultData(String vaultBlock, String attributeName, VaultEntry entry) {
		vaultData.put(dataKey(vaultBlock, attributeName), entry);
	}

	/**
	 * Removes data stored in vault storage.
	 * 
	 * @param vaultBlock
	 *            the block location in the vault
	 * @param attributeName
	 *            the attribute name within the block
	 * @return true when vault data has been removed successfully, otherwise
	 *         false
	 */
	boolean deleteVaultData(String vaultBlock, String attributeName) {
		if (vaultData.remove(dataKey(vaultBlock, attributeName)) == null) {
			return false;
		}
		return true;
	}

	/**
	 * Returns mapping keys for all stored data.
	 * 
	 * @return set of keys to the vaulted passwords
	 */
	Set<String> getVaultDataKeys() {
		return vaultData.keySet();
	}

	/**
	 * Creates new format for data key in vault. All parameters has to be
	 * non-null.
	 * 
	 * @param vaultBlock
	 *            the block in the vault where the attribute is stored
	 * @param attributeName
	 *            the name of the attribute
	 * @return key to lookup information in the vault
	 */
	private static String dataKey(String vaultBlock, String attributeName) {
		return vaultBlock + StringUtil.PROPERTY_DEFAULT_SEPARATOR + attributeName;
	}
}