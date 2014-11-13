/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
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
 *     org.jboss.as.security.vault.VaultTool
 *
 * The full header for that file is included above.
 */
package org.jboss.security.fips.tools;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;

import org.jboss.security.fips.plugins.FIPSCompliantVault;
import org.jboss.security.fips.plugins.FIPSCompliantVaultData;
import org.jboss.security.fips.utils.FIPSCryptoUtil;
import org.jboss.security.fips.utils.FIPSVaultFileUtil;
import org.jboss.security.fips.utils.FIPSVaultOptions;
import org.jboss.security.vault.SecurityVault;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

/**
 * Command Line Tool for the FIPS-140 compliant implementation of the
 * {@link SecurityVault}
 * 
 * @author Rich Lucente
 */
public class VaultTool {

	private FIPSVaultFileUtil fileUtil = new FIPSVaultFileUtil();
	private FIPSVaultOptions options = new FIPSVaultOptions();
	private SecurityVault vault = new FIPSCompliantVault();
	private VaultInteraction interaction = null;

	public static void main(String[] args) throws Exception {
		VaultTool tool = new VaultTool(args);
		tool.init();

		Scanner in = new Scanner(System.in);
		boolean running = true;
		while (running) {
			String commandStr = "Please enter a Digit::   0: Start Interaction "
					+ " 1: Remove Interaction " + " 2: Exit";

			System.out.println(commandStr);
			int choice = in.nextInt();
			switch (choice) {
			case 0:
				System.out.println("Starting a vault interaction");
				tool.startInteraction();
				break;
			case 1:
				System.out.println("Removing the current vault interaction");
				tool.stopInteraction();
				break;
			default:
				running = false;
			}
		}

		if (in != null)
			in.close();

		System.exit(0);
	}

	/**
	 * Constructor that parses command line args
	 * 
	 * @param args
	 *            command line arguments
	 */
	VaultTool(String[] args) {
		try {
			options.parseArgs(args);
		} catch (Exception e) {
			options.printUsage();
			e.printStackTrace(System.err);
			System.exit(2);
		}
	}

	/**
	 * Initialize the vault tool. Prompts for the FIPS token PIN and then
	 * generates a salt and iv value if needed. If this is a new vault, the
	 * vault-options are printed for the user to add to the EAP configuration
	 * file. Finally, the vault itself is initialized so sensitive strings can
	 * be added.
	 * 
	 * @throws Exception
	 *             if problem with cryptography or file operations.
	 */
	void init() throws Exception {
		// login to the FIPS crypto token
		Password tokenPin = FIPSCryptoUtil
				.readSensitiveString("FIPS Token PIN");
		CryptoToken fipsToken = CryptoManager.getInstance()
				.getInternalKeyStorageToken();
		fipsToken.login(tokenPin);

		// Generate random salt and IV to mask the token PIN. Always do this,
		// even if vault-options already exist since we need to send a valid map
		// of key/value pairs to initialize the vault itself
		Provider fipsProvider = Security
				.getProvider(FIPSCryptoUtil.FIPS_PROVIDER_NAME);
		SecureRandom random = SecureRandom.getInstance(
				FIPSCryptoUtil.PRNG_ALGORITHM, fipsProvider);

		byte[] salt = new byte[FIPSCryptoUtil.PBE_SALT_MIN_LEN];
		random.nextBytes(salt);
		options.setSalt(salt);

		byte[] iv = new byte[DESKeySpec.DES_KEY_LEN];
		random.nextBytes(iv);
		options.setIv(iv);

		// mask the token pin
		SecretKey maskKey = FIPSCryptoUtil.fipsDeriveMaskKey(fipsToken, salt);
		byte[] maskedToken = FIPSCryptoUtil.maskTokenPin(tokenPin, maskKey, iv);
		options.setMaskedTokenPin(maskedToken);

		Map<String, Object> vaultOptions = options.getVaultOptionMap();

		// if this is a new vault, seed the vault with an admin key and print
		// the vault-options
		if (options.isNewVault()) {
			// generate a random admin key
			SecretKey adminKey = FIPSCryptoUtil.generateAdminKey();
			byte[] wrappedKey = FIPSCryptoUtil.wrapKey(fipsToken, adminKey);

			// add the key to the vault content
			FIPSCompliantVaultData vaultContent = new FIPSCompliantVaultData();
			vaultContent.addVaultData(FIPSCompliantVault.ADMIN_KEY_VAULTBLOCK,
					FIPSCompliantVault.ADMIN_KEY_ATTRIBUTE, wrappedKey);

			// write the content file
			fileUtil.writeVaultData(vaultContent);

			// print the vault-option elements
			vaultConfigurationDisplay();
		}

		// initialize the password vault
		vault.init(vaultOptions);
	}

	/**
	 * Starts the interaction with the vault.
	 */
	void startInteraction() {
		interaction = new VaultInteraction(vault);
		interaction.start();
	}

	/**
	 * Stops the interaction with the vault.
	 */
	void stopInteraction() {
		interaction = null;
	}

	/**
	 * Display info about vault itself in form of EAP configuration file.
	 */
	public void vaultConfigurationDisplay() {
		System.out.println("\n********************************************");
		System.out.println("NOTE:  Make sure that the EAP configuration "
				+ "file includes the following elements:");
		System.out.println("********************************************");
		System.out.println("...");
		System.out.println("</extensions>");
		System.out.println(vaultConfiguration());
		System.out.println("<management>");
		System.out.println("...");
		System.out.println("********************************************\n");
	}

	/**
	 * @return vault configuration string in user readable form.
	 */
	public String vaultConfiguration() {
		StringBuilder sb = new StringBuilder();
		sb.append(
				"<vault code=\"" + FIPSCompliantVault.class.getName()
						+ "\" module=\"org.jboss.security.fips.plugins\" >")
				.append("\n");

		Map<String, Object> vaultOptions = options.getVaultOptionMap();
		for (String key : vaultOptions.keySet()) {
			sb.append(
					"  <vault-option name=\"" + key + "\" value=\""
							+ vaultOptions.get(key) + "\"/>").append("\n");
		}

		sb.append("</vault>");
		return sb.toString();
	}
}