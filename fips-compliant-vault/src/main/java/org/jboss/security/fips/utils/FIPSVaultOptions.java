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

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.DESKeySpec;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.jboss.security.Base64Utils;

/**
 * Utility functions for FIPS vault options.
 * 
 * @author Rich Lucente
 * @since Nov 5, 2014
 */
public class FIPSVaultOptions {
	// vault-option names and parsing constants
	private static final String IV = "IV";
	private static final String MASKED_TOKEN_PIN = "TOKEN_PIN";
	private static final String MASKED_TOKEN_PREFIX = "MASK-";
	private static final String SALT = "SALT";

	// command-line parsing
	private static final String IS_NEW_VAULT_PARAM = "new-vault";
	private static final String HELP_PARAM = "help";
	private static final String APP_NAME = "java -jar org.jboss.security.fips.tools.VaultTool";
	private static final int HELP_WIDTH = 72;

	private Options options = null;
	
	// vault options
	private byte[] iv = null;
	private byte[] maskedTokenPin = null;
	private byte[] salt = null;
	private Map<String, Object> optionMap = new HashMap<String, Object>();
	
	// command line options
	private boolean isNewVault = false;
	private boolean isHelpRequested = false;

	/**
	 * Default ctor
	 */
	public FIPSVaultOptions() {
	}

	/**
	 * @return map of vault options
	 */
	public Map<String, Object> getVaultOptionMap() {	
		return optionMap;
	}

	/**
	 * @return the raw byte array for the initialization vector used to mask the
	 *         FIPS token PIN.
	 */
	public byte[] getIv() {
		return iv;
	}

	/**
	 * @return the raw byte array of the encrypted FIPS token PIN.
	 */
	public byte[] getMaskedTokenPin() {
		return maskedTokenPin;
	}

	/**
	 * @return the raw byte array for the salt used to mask the FIPS token PIN.
	 */
	public byte[] getSalt() {
		return salt;
	}

	/**
	 * @return true if this is a newly created vault
	 */
	public boolean isNewVault() {
		return isNewVault;
	}

	/**
	 * @return true if help has been requested
	 */
	public boolean isHelpRequested() {
		return isHelpRequested;
	}

	/**
	 * Set initialization vector to mask/unmask the token PIN.
	 * 
	 * @param iv
	 *            the initialization vector
	 */
	public void setIv(byte[] iv) {
		this.iv = iv;
		optionMap.put(IV, Base64Utils.tob64(iv));
	}

	/**
	 * Set encrypted FIPS token PIN.
	 * 
	 * @param maskedTokenPin
	 *            the encrypted token PIN
	 */
	public void setMaskedTokenPin(byte[] maskedTokenPin) {
		this.maskedTokenPin = maskedTokenPin;
		optionMap.put(MASKED_TOKEN_PIN, MASKED_TOKEN_PREFIX + Base64Utils.tob64(maskedTokenPin));
	}

	/**
	 * Set the salt
	 * 
	 * @param salt
	 *            the salt to mask/unmask the token PIN
	 */
	public void setSalt(byte[] salt) {
		this.salt = salt;
		optionMap.put(SALT, Base64Utils.tob64(salt));
	}

	/**
	 * Parse the given command line arguments. Values are available via getter
	 * functions.
	 */
	public void parseArgs(String[] args) throws Exception {
		initOptions();
		parseCmdLine(args);
	}

	/**
	 * Print the help for the command line options.
	 */
	public void printUsage() {
		HelpFormatter formatter = new HelpFormatter();
		PrintWriter pw = new PrintWriter(System.err);
		formatter.printUsage(pw, HELP_WIDTH, APP_NAME, options);
	}

	/**
	 * Validates that the initialization vector is a valid base-64 encoded
	 * string with the expected length.
	 * 
	 * @param ivOptVal
	 *            the initialization vector as a base-64 encoded string
	 * @throws IllegalArgumentException
	 *             if IV is missing, not a base-64 encoded value, or not correct
	 *             length
	 */
	public void validateIvOption(String ivOptVal)
			throws IllegalArgumentException {
		if (ivOptVal == null)
			throw new IllegalArgumentException("missing required option " + IV);

		try {
			setIv(Base64Utils.fromb64(ivOptVal));
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException(
					"initialization vector is not a valid base-64 encoded byte array",
					nfe);
		}

		if (iv.length != DESKeySpec.DES_KEY_LEN)
			throw new IllegalArgumentException("initialization vector must be "
					+ DESKeySpec.DES_KEY_LEN + " bytes in length");
	}

	/**
	 * Validates that the salt is a valid base-64 encoded string with the
	 * expected length.
	 * 
	 * @param saltOptVal
	 *            the salt as a base-64 encoded string
	 * @throws IllegalArgumentException
	 *             if salt is missing, not a base-64 encoded value, or not
	 *             correct length
	 */
	public void validateSaltOption(String saltOptVal)
			throws IllegalArgumentException {
		if (saltOptVal == null)
			throw new IllegalArgumentException("missing required option "
					+ SALT);

		try {
			setSalt(Base64Utils.fromb64(saltOptVal));
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException(
					"salt is not a valid base-64 encoded byte array", nfe);
		}

		if (salt.length < FIPSCryptoUtil.PBE_SALT_MIN_LEN)
			throw new IllegalArgumentException("salt must be at least "
					+ FIPSCryptoUtil.PBE_SALT_MIN_LEN + " bytes in length");
	}

	/**
	 * Validates that the masked token PIN is a valid base-64 encoded string
	 * with the expected prefix.
	 * 
	 * @param maskedTokenPinOptVal
	 *            the masked token PIN as a base-64 encoded string with expected
	 *            prefix
	 * @throws IllegalArgumentException
	 *             if masked token PIN is missing, not a base-64 encoded value,
	 *             or does not have the expected prefix
	 */
	public void validateTokenPin(String maskedTokenPinOptVal)
			throws IllegalArgumentException {
		if (maskedTokenPinOptVal == null)
			throw new IllegalArgumentException("missing required option "
					+ MASKED_TOKEN_PIN);

		if (maskedTokenPinOptVal.startsWith(MASKED_TOKEN_PREFIX) == false)
			throw new IllegalArgumentException("invalid masked token pin '"
					+ maskedTokenPinOptVal + "'");

		maskedTokenPinOptVal = maskedTokenPinOptVal
				.substring(MASKED_TOKEN_PREFIX.length());
		try {
			setMaskedTokenPin(Base64Utils.fromb64(maskedTokenPinOptVal));
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException(
					"masked token PIN is not a valid base-64 encoded byte array",
					nfe);
		}
	}

	/**
	 * Validate the expected vault-options for the FIPS compliant vault.
	 * 
	 * @param options
	 *            the map of name/value pairs for the vault-options
	 * @throws IllegalArgumentException
	 *             when no options or options are not valid
	 */
	public void validateVaultOptions(Map<String, Object> options)
			throws IllegalArgumentException {
		if (options == null || options.isEmpty())
			throw new IllegalArgumentException(
					"required options missing or empty");

		String maskedTokenPinOptVal = (String) options.get(MASKED_TOKEN_PIN);
		validateTokenPin(maskedTokenPinOptVal);

		String saltOptVal = (String) options.get(SALT);
		validateSaltOption(saltOptVal);

		String ivOptVal = (String) options.get(IV);
		validateIvOption(ivOptVal);
	}

	/**
	 * Build the command line options for the vault tool
	 */
	private void initOptions() {
		options = new Options();

		OptionGroup og = new OptionGroup();
		Option n = new Option("n", IS_NEW_VAULT_PARAM, false,
				"This is a newly created vault");
		Option h = new Option("h", HELP_PARAM, false, "Help");
		og.addOption(n);
		og.addOption(h);
		options.addOptionGroup(og);
	}

	/**
	 * Parse the command line arguments
	 */
	private void parseCmdLine(String[] args) throws Exception {
		PosixParser parser = new PosixParser();
		CommandLine cmdLine = parser.parse(options, args, true);

		if (cmdLine.hasOption("n"))
			isNewVault = true;

		if (cmdLine.hasOption("h"))
			isHelpRequested = true;
	}
}
