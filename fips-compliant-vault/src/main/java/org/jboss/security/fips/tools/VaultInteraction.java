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
 * This class is derived from org.jboss.as.security.vault.VaultInteraction.java.
 * The header from that class is above.
 */
package org.jboss.security.fips.tools;

import java.util.Scanner;

import org.jboss.security.fips.utils.FIPSCryptoUtil;
import org.jboss.security.vault.SecurityVault;
import org.mozilla.jss.util.Password;

/**
 * Interaction with initialized {@link SecurityVault} via the {@link VaultTool}
 *
 * @author Anil Saldhana
 * @author Rich Lucente
 */
public class VaultInteraction {
	private static final long FAKE_SHARED_KEY = 0x464950532d313430L;

	private SecurityVault vault = null;
	private byte[] sharedKey = new byte[1];

	public VaultInteraction(SecurityVault vault) {
		this.vault = vault;
	}

	public void start() {
		Scanner in = new Scanner(System.in);
		while (true) {
			String commandStr = "Please enter a Digit::   0: Store a secured attribute "
					+ " 1: Check whether a secured attribute exists "
					+ " 2: Exit";

			System.out.println(commandStr);
			int choice = in.nextInt();
			switch (choice) {
			case 0:
				System.out.println("Task: Store a secured attribute");

				Password attributeValue = FIPSCryptoUtil
						.readSensitiveString("secured attribute value (such as password)");

				String vaultBlock = readValue(in, "Vault Block");
				String attributeName = readValue(in, "Attribute Name");

				try {
					vault.store(vaultBlock, attributeName,
							attributeValue.getChars(), sharedKey);
					attributeCreatedDisplay(vaultBlock, attributeName);
				} catch (Exception e) {
					System.out.println("Exception occurred:"
							+ e.getLocalizedMessage());
				} finally {
					attributeValue.clear();
				}
				break;

			case 1:
				System.out
						.println("Task: Verify whether a secured attribute exists");

				vaultBlock = readValue(in, "Vault Block");
				attributeName = readValue(in, "Attribute Name");

				try {
					char[] value = vault.retrieve(vaultBlock, attributeName,
							sharedKey);
					if (value == null || value.length == 0)
						System.out.println("No value has been stored for ("
								+ vaultBlock + ", " + attributeName + ")");
					else {
						Password.wipeChars(value);
						System.out.println("A value exists for (" + vaultBlock
								+ ", " + attributeName + ")");
					}
				} catch (Exception e) {
					System.out.println("Exception occurred:"
							+ e.getLocalizedMessage());
				}
				break;

			default:
				System.exit(0);
			}
		}
	}

	/**
	 * Display info about stored secured attribute.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 */
	private void attributeCreatedDisplay(String vaultBlock, String attributeName) {
		System.out
				.println("\nSecured attribute value has been stored in vault. ");
		System.out.println("Please make note of the following:");
		System.out.println("********************************************");
		System.out.println("Vault Block:" + vaultBlock);
		System.out.println("Attribute Name:" + attributeName);
		System.out.println("Configuration should be done as follows:");
		System.out.println(securedAttributeConfigurationString(vaultBlock,
				attributeName));
		System.out.println("********************************************\n");
	}

	/**
	 * Reads a value from the input stream using the given prompt
	 * 
	 * @param in
	 *            the input scanner
	 * @return the value read from the console
	 */
	private String readValue(Scanner in, String prompt) {
		String value = null;

		while (value == null || value.length() == 0) {
			System.out.print("Enter " + prompt + ": ");
			value = in.nextLine().trim();
		}

		return value;
	}

	/**
	 * Returns configuration string for secured attribute.
	 *
	 * @param vaultBlock
	 * @param attributeName
	 * @return
	 */
	private String securedAttributeConfigurationString(String vaultBlock,
			String attributeName) {
		return "VAULT::" + vaultBlock + "::" + attributeName + "::" + FAKE_SHARED_KEY;
	}
}