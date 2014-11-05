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

import java.util.Map;

import javax.crypto.spec.DESKeySpec;

import org.jboss.security.Base64Utils;

/**
 * Utility functions for FIPS vault options.
 * 
 * @author Rich Lucente
 * @since Nov 5, 2014
 */
public class FIPSVaultOptions {
	// vault-option names and parsing constants
	public static final String IV = "IV";
	public static final String MASKED_TOKEN_PIN = "TOKEN_PIN";
	public static final String MASKED_TOKEN_PREFIX = "MASK-";
	public static final String SALT = "SALT";

	// NIST Special Publication 800-132 recommendations for PBKDF2 algorithm
	public static final int PBE_SALT_MIN_LEN = 128 / 8;

	// vault options
	private byte[] iv = null;
	private String maskedTokenPin = null;
	private byte[] salt = null;

	public FIPSVaultOptions() {
	}

	public String getEncodedIv() {
		return Base64Utils.tob64(iv);
	}

	public String getEncodedSalt() {
		return Base64Utils.tob64(salt);
	}

	public byte[] getIv() {
		return iv;
	}

	public String getMaskedTokenPin() {
		return maskedTokenPin;
	}

	public byte[] getSalt() {
		return salt;
	}

	public void validateAllOptions(Map<String, Object> options)
			throws IllegalArgumentException {
		if (options == null || options.isEmpty())
			throw new IllegalArgumentException(
					"required options missing or empty");

		maskedTokenPin = (String) options.get(MASKED_TOKEN_PIN);
		validateTokenPin();

		String saltOptVal = (String) options.get(SALT);
		validateSaltOption(saltOptVal);

		String ivOptVal = (String) options.get(IV);
		validateIvOption(ivOptVal);
	}

	public void validateIvOption(String ivOptVal)
			throws IllegalArgumentException {
		if (ivOptVal == null)
			throw new IllegalArgumentException("missing required option " + IV);

		try {
			iv = Base64Utils.fromb64(ivOptVal);
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException(
					"initialization vector is not a valid base-64 encoded byte array",
					nfe);
		}

		if (iv.length != DESKeySpec.DES_KEY_LEN)
			throw new IllegalArgumentException("initialization vector must be "
					+ DESKeySpec.DES_KEY_LEN + " bytes in length");
	}

	public void validateSaltOption(String saltOptVal)
			throws IllegalArgumentException {
		if (saltOptVal == null)
			throw new IllegalArgumentException("missing required option "
					+ SALT);

		try {
			salt = Base64Utils.fromb64(saltOptVal);
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException(
					"salt is not a valid base-64 encoded byte array", nfe);
		}

		if (salt.length < PBE_SALT_MIN_LEN)
			throw new IllegalArgumentException("salt must be at least "
					+ PBE_SALT_MIN_LEN + " bytes in length");
	}

	public void validateTokenPin() throws IllegalArgumentException {
		if (maskedTokenPin == null)
			throw new IllegalArgumentException("missing required option "
					+ MASKED_TOKEN_PIN);

		if (maskedTokenPin.startsWith(MASKED_TOKEN_PREFIX) == false)
			throw new IllegalArgumentException("invalid masked token pin '"
					+ maskedTokenPin + "'");
	}
}
