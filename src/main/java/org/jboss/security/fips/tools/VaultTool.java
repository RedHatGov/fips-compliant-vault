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
import java.util.InputMismatchException;
import java.util.Scanner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.bouncycastle.util.encoders.Base64;
import org.jboss.security.fips.utils.CryptoUtil;
import org.jboss.security.vault.SecurityVault;

/**
 * Command Line Tool for the default implementation of the {@link SecurityVault}
 *
 * @author Anil Saldhana
 * @author Peter Skopek
 */
public class VaultTool {

	public static final String KEYSTORE_PARAM = "keystore";
	public static final String KEYSTORE_PASSWORD_PARAM = "keystore-password";
	public static final String ENC_DIR_PARAM = "enc-dir";
	public static final String SALT_PARAM = "salt";
	public static final String ITERATION_PARAM = "iteration";
	public static final String ALIAS_PARAM = "alias";
	public static final String IV_PARAM = "iv";
	public static final String VAULT_BLOCK_PARAM = "vault-block";
	public static final String ATTRIBUTE_PARAM = "attribute";
	public static final String SEC_ATTR_VALUE_PARAM = "sec-attr";
	public static final String CHECK_SEC_ATTR_EXISTS_PARAM = "check-sec-attr";
	public static final String REMOVE_SEC_ATTR_PARAM = "remove-sec-attr";
	public static final String CREATE_KEYSTORE_PARAM = "create-keystore";
	public static final String HELP_PARAM = "help";

	private VaultInteractiveSession session = null;
	private VaultSession nonInteractiveSession = null;

	private Options options = null;
	private CommandLineParser parser = null;
	private CommandLine cmdLine = null;

	public void setSession(VaultInteractiveSession sess) {
		session = sess;
	}

	public VaultInteractiveSession getSession() {
		return session;
	}

	public static void main(String[] args) {

		VaultTool tool = null;

		if (args != null && args.length > 0) {
			int returnVal = 0;
			try {
				tool = new VaultTool(args);
				returnVal = tool.execute();
			} catch (Exception e) {
				System.err.println("Problem occured:");
				e.printStackTrace(System.err);
				System.exit(1);
			}
			System.exit(returnVal);
		} else {
			tool = new VaultTool();

			System.out.println("**********************************");
			System.out.println("****  JBoss Vault  ***************");
			System.out.println("**********************************");

			Console console = System.console();

			if (console == null) {
				System.err.println("No console.");
				System.exit(1);
			}

			Scanner in = new Scanner(System.in);
			while (true) {
				String commandStr = "Please enter a Digit::   0: Start Interactive Session "
						+ " 1: Remove Interactive Session " + " 2: Exit";

				System.out.println(commandStr);
				try {
					int choice = in.nextInt();
					switch (choice) {
					case 0:
						System.out.println("Starting an interactive session");
						VaultInteractiveSession vsession = new VaultInteractiveSession();
						tool.setSession(vsession);
						vsession.start();
						break;
					case 1:
						System.out.println("Removing the current interactive session");
						tool.setSession(null);
						break;
					default:
						in.close();
						System.exit(0);
					}
				} catch (InputMismatchException e) {
					in.close();
					System.exit(0);
				}
			}
		}
	}

	public VaultTool(String[] args) {
		initOptions();
		parser = new PosixParser();
		try {
			cmdLine = parser.parse(options, args, true);
		} catch (ParseException e) {
			System.out.println("Problem while parsing command line parameters:");
			e.printStackTrace(System.err);
			System.exit(2);
		}
	}

	public VaultTool() {
	}

	/**
	 * Build options for non-interactive VaultTool usage scenario.
	 *
	 * @return
	 */
	private void initOptions() {
		options = new Options();
		options.addOption("k", KEYSTORE_PARAM, true, "Keystore URL");
		options.addOption("p", KEYSTORE_PASSWORD_PARAM, true, "The plaintext password -OR- "
				+ "the base-64 encoded masked keystore password -OR- " + "a valid password command");
		options.addOption("e", ENC_DIR_PARAM, true, "Directory containing encrypted files");
		options.addOption("s", SALT_PARAM, true,
				"base-64 encoded salt of at least 128 bits in length before encoding.  "
						+ "DEFAULT random value generated.");
		options.addOption("i", ITERATION_PARAM, true, "Iteration count of at least 1000.  " + "DEFAULT 1000.");
		options.addOption("v", ALIAS_PARAM, true, "Vault admin key alias.  DEFAULT 'adminKey'.");
		options.addOption("c", IV_PARAM, true,
				"base-64 encoded initialization vector that's 128 bits in length before encoding.  "
						+ "DEFAULT random value generated.");
		options.addOption("b", VAULT_BLOCK_PARAM, true, "Vault block");
		options.addOption("a", ATTRIBUTE_PARAM, true, "Attribute name");
		options.addOption("t", CREATE_KEYSTORE_PARAM, false, "Automatically create keystore when it doesn't exist");

		OptionGroup og = new OptionGroup();
		Option x = new Option("x", SEC_ATTR_VALUE_PARAM, true,
				"Add secured attribute value (such as password) to store");
		Option c = new Option("c", CHECK_SEC_ATTR_EXISTS_PARAM, false,
				"Check whether the secured attribute already exists in the vault");
		Option r = new Option("r", REMOVE_SEC_ATTR_PARAM, false, "Remove secured attribute from the Vault");
		Option h = new Option("h", HELP_PARAM, false, "Help");
		og.addOption(x);
		og.addOption(c);
		og.addOption(r);
		og.addOption(h);
		og.setRequired(true);
		options.addOptionGroup(og);
	}

	private int execute() throws Exception {

		if (cmdLine.hasOption(HELP_PARAM)) {
			printUsage();
			return 100;
		}

		String keystoreURL = cmdLine.getOptionValue(KEYSTORE_PARAM, "vault.bcfks");
		String keystorePasswordStr = cmdLine.getOptionValue(KEYSTORE_PASSWORD_PARAM, "");
		String encryptionDirectory = cmdLine.getOptionValue(ENC_DIR_PARAM, "vault");

		byte[] salt = CryptoUtil.genRandomBytes(CryptoUtil.PBE_SALT_MIN_LEN);
		if (cmdLine.hasOption(SALT_PARAM)) {
			try {
				salt = Base64.decode(cmdLine.getOptionValue(SALT_PARAM));
			} catch (Throwable t) {
				System.out.println("The given salt, " + cmdLine.getOptionValue(SALT_PARAM)
						+ ", is not a valid base-64 encoded string.");
				printUsage();
				return -1;
			}
		}

		int iterationCount = Integer.parseInt(cmdLine.getOptionValue(ITERATION_PARAM, "1000"));

		byte[] iv = CryptoUtil.genRandomBytes(CryptoUtil.MASK_KEY_STRENGTH / 8);
		if (cmdLine.hasOption(IV_PARAM)) {
			try {
				iv = Base64.decode(cmdLine.getOptionValue(IV_PARAM));
			} catch (Throwable t) {
				System.out.println("The given initialization vector, " + cmdLine.getOptionValue(IV_PARAM)
						+ ", is not a valid base-64 encoded string.");
				printUsage();
				return -1;
			}
		}

		char[] keystorePassword = keystorePasswordStr.toCharArray();

		boolean createKeyStore = cmdLine.hasOption(CREATE_KEYSTORE_PARAM);

		nonInteractiveSession = new VaultSession(keystoreURL, keystorePassword, encryptionDirectory, salt,
				iterationCount, iv, createKeyStore);

		nonInteractiveSession.startVaultSession(cmdLine.getOptionValue(ALIAS_PARAM, "adminKey"));

		String vaultBlock = cmdLine.getOptionValue(VAULT_BLOCK_PARAM, "vb");
		String attributeName = cmdLine.getOptionValue(ATTRIBUTE_PARAM, "password");

		if (cmdLine.hasOption(CHECK_SEC_ATTR_EXISTS_PARAM)) {
			// check password
			if (nonInteractiveSession.checkSecuredAttribute(vaultBlock, attributeName)) {
				System.out.println("Password already exists.");
				summary();
				return 0;
			} else {
				System.out.println("Password doesn't exist.");
				return 5;
			}
		} else if (cmdLine.hasOption(REMOVE_SEC_ATTR_PARAM)) {
			// remove password
			if (nonInteractiveSession.removeSecuredAttribute(vaultBlock, attributeName)) {
				System.out.println(
						"Secured attribute " + VaultSession.blockAttributeDisplayFormat(vaultBlock, attributeName)
								+ " has been successfuly removed from vault");
				return 0;
			} else {
				System.out.println(
						"Secured attribute " + VaultSession.blockAttributeDisplayFormat(vaultBlock, attributeName)
								+ " was not removed from vault, check whether it exist");
				return 6;
			}

		} else if (cmdLine.hasOption(SEC_ATTR_VALUE_PARAM)) {
			// add password
			String password = cmdLine.getOptionValue(SEC_ATTR_VALUE_PARAM, "password");
			nonInteractiveSession.addSecuredAttributeWithDisplay(vaultBlock, attributeName, password.toCharArray());
			summary();
			return 0;
		} else {
			System.out.println("Action not specified.");
			return -1;
		}
	}

	private void summary() {
		nonInteractiveSession.vaultConfigurationDisplay();
	}

	private void printUsage() {
		HelpFormatter help = new HelpFormatter();
		String suffix = (VaultTool.isWindows() ? ".bat" : ".sh");
		help.printHelp("fips-vault" + suffix + " <empty> | ", options, true);
	}

	public static boolean isWindows() {
		String opsys = System.getProperty("os.name").toLowerCase();
		return (opsys.indexOf("win") >= 0);
	}
}