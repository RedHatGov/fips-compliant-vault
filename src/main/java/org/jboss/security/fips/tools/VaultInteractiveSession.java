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
package org.jboss.security.fips.tools;

import java.io.Console;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Base64;
import org.jboss.security.fips.utils.CryptoUtil;

/**
 * An interactive session for {@link VaultTool}
 *
 * @author Anil Saldhana
 * @author Rich Lucente <rlucente_at_redhat_dot_com>
 */
public class VaultInteractiveSession {

	private String keystoreURL, encDir, keystoreAlias;
	private byte[] salt = null;
	private int iterationCount = 0;
	private byte[] iv = null;
	private boolean createKeystore = false;
	
	// vault non-interactive session
	private VaultSession vaultNISession = null;

	public VaultInteractiveSession() {
	}

	public void start() {
		Console console = System.console();

		if (console == null) {
			System.err.println("No console.");
			System.exit(1);
		}

		while (encDir == null || encDir.length() == 0) {
			encDir = console.readLine("\nEnter directory to store encrypted files: ");
		}

		while (keystoreURL == null || keystoreURL.length() == 0) {
			keystoreURL = console.readLine("\nEnter Keystore URL: ");
		}

		String createKeystoreStr = null;
		while (createKeystoreStr == null || createKeystoreStr.trim().isEmpty()) {
			createKeystoreStr = console.readLine("\nCreate the keystore if it doesn't exist <y/N>: ");
			if (createKeystoreStr.contains("Y") || createKeystoreStr.contains("y"))
				createKeystore = true;
		}

		char[] keystorePasswd = readSensitiveValue("keystore password");

		try {
			while (salt == null) {
				System.out.println("\nThe salt must be at least " + CryptoUtil.PBE_SALT_MIN_LEN
						+ " bytes in length, before base-64 encoding.");
				String saltStr = console.readLine("Enter salt as a base-64 string (or ENTER for a random value): ");

				try {
					if (saltStr.trim().isEmpty()) {
						salt = CryptoUtil.genRandomBytes(CryptoUtil.PBE_SALT_MIN_LEN);
					} else {
						salt = Base64.decode(saltStr);
					}
				} catch (Throwable t) {
					System.out.println("The salt is not a valid base-64 encoded string.");
					salt = null;
				}

				if (salt != null && salt.length < CryptoUtil.PBE_SALT_MIN_LEN) {
					System.out.println("The salt is not at least " + CryptoUtil.PBE_SALT_MIN_LEN + " bytes in length.");
					salt = null;
				}
			}

			System.out.println("\nThe iteration count must be at least " + CryptoUtil.PBE_MIN_ITERATION_COUNT);
			String ic = console.readLine("Enter iteration count as a number (Eg: 2000): ");
			iterationCount = Integer.parseInt(ic);

			while (iv == null) {
				System.out.println("\nThe initialization vector must be " + CryptoUtil.MASK_KEY_STRENGTH / 8
						+ " bytes in length, before base-64 encoding.");
				String ivStr = console.readLine("Enter iv as a base-64 string (or ENTER for a random value): ");

				try {
					if (ivStr.trim().isEmpty()) {
						iv = CryptoUtil.genRandomBytes(CryptoUtil.MASK_KEY_STRENGTH / 8);
					} else {
						iv = Base64.decode(ivStr);
					}
				} catch (Throwable t) {
					System.out.println("The iv is not a valid base-64 encoded string.");
					iv = null;
				}

				if (iv.length != CryptoUtil.MASK_KEY_STRENGTH / 8) {
					System.out.println("The iv is not " + CryptoUtil.MASK_KEY_STRENGTH / 8 + " bytes in length.");
					iv = null;
				}
			}

			vaultNISession = new VaultSession(keystoreURL, keystorePasswd, encDir, salt, iterationCount,
					iv, createKeystore);

			while (keystoreAlias == null || keystoreAlias.length() == 0) {
				keystoreAlias = console.readLine("\nEnter Keystore Alias: ");
			}

			System.out.println("\nInitializing Vault");
			vaultNISession.startVaultSession(keystoreAlias);
			vaultNISession.vaultConfigurationDisplay();

			System.out.println("Vault is initialized and ready for use");

			VaultInteraction vaultInteraction = new VaultInteraction(vaultNISession);
			vaultInteraction.start();
		} catch (Exception e) {
			System.out.println("Exception encountered: " + e.getLocalizedMessage());
		}
	}

	public static char[] readSensitiveValue(String prompt) {
		char[] first = null;
		char[] second = null;

		Console console = System.console();
		if (console != null) {
			do {
				if (first != null) {
					System.out.println("\nThe values do not match.  " + "Please try again.");
				}

				first = console.readPassword("\nPlease enter the %s: ", prompt);
				second = console.readPassword("Please confirm the %s: ", prompt);
			} while (!Arrays.equals(first, second));

			// wipe the temporary data
			if (second != null)
				Arrays.fill(second, (char) 0);
		}

		return first;
	}

}