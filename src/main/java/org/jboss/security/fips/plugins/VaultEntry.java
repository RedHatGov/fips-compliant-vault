/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
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