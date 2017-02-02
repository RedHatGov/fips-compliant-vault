package org.jboss.security.fips;

import javax.security.auth.login.LoginException;
import org.jboss.logging.Cause;
import org.jboss.logging.Message;
import org.jboss.logging.MessageBundle;
import org.jboss.logging.Messages;

@SuppressWarnings("deprecation")
@MessageBundle(projectCode = "FIPS")
public interface FIPSVaultMessages {

	FIPSVaultMessages MESSAGES = Messages.getBundle(FIPSVaultMessages.class);

	@Message(id = 4, value = "Argument %s cannot be null")
	IllegalArgumentException invalidNullArgument(String argumentName);

	@Message(id = 6, value = "Unable to load vault class")
	String unableToLoadVaultMessage();

	@Message(id = 7, value = "Unable to instantiate vault class")
	String unableToCreateVaultMessage();

	@Message(id = 8, value = "Vault is not initialized")
	String vaultNotInitializedMessage();

	@Message(id = 9, value = "Invalid vaultString format: %s")
	IllegalArgumentException invalidVaultStringFormat(String vaultString);

	@Message(id = 69, value = "Unable to get password value from vault at %s:%s")
	LoginException unableToGetPasswordFromVault(String vaultBlock, String attribute);

	@Message(id = 112, value = "Invalid Base64 string: %s")
	IllegalArgumentException invalidBase64String(String base64Str);

	@Message(id = 118, value = "Invalid password command type: %s")
	IllegalArgumentException invalidPasswordCommandType(String type);

	@Message(id = 120, value = "Options map %s is null or empty")
	IllegalArgumentException invalidNullOrEmptyOptionMap(String mapName);

	@Message(id = 121, value = "Option %s is null or empty")
	String invalidNullOrEmptyOptionMessage(String optionName);

	@Message(id = 122, value = "Keystore password %s must be a base64 encoded encrypted password")
	IllegalArgumentException invalidUnmaskedKeystorePasswordMessage(@Cause Throwable t, String password);

	@Message(id = 123, value = "File or directory %s does not exist")
	String fileOrDirectoryDoesNotExistMessage(String fileName);

	@Message(id = 124, value = "Directory %s does not end with / or \\")
	String invalidDirectoryFormatMessage(String directory);

	@Message(id = 128, value = "Unable to encrypt data")
	String unableToEncryptDataMessage();

	@Message(id = 130, value = "Unable to write vault data file (%s)")
	String unableToWriteVaultDataFileMessage(String fileName);

	@Message(id = 132, value = "The specified system property %s is missing")
	IllegalArgumentException missingSystemProperty(String sysProperty);

	@Message(id = 133, value = "Failed to match %s and %s")
	RuntimeException failedToMatchStrings(String one, String two);

	@Message(id = 137, value = "Security Vault does not contain SecretKey entry under alias (%s)")
	RuntimeException vaultDoesnotContainSecretKey(String alias);

	@Message(id = 138, value = "There is no SecretKey under the alias (%s) and the alias is already used to denote diffrent crypto object in the keystore.")
	RuntimeException noSecretKeyandAliasAlreadyUsed(String alias);

	@Message(id = 139, value = "Unable to store keystore to file (%s)")
	RuntimeException unableToStoreKeyStoreToFile(@Cause Throwable throwable, String file);

	@Message(id = 140, value = "Unable to get keystore (%s)")
	RuntimeException unableToGetKeyStore(@Cause Throwable throwable, String file);

	@Message(id = 142, value = "Keystore password should be either masked or prefixed with one of {EXT}, {EXTC}, {CMD}, {CMDC}, {CLASS}")
	String invalidKeystorePasswordFormatMessage();

	@Message(id = 143, value = "Unable to load password class (%s). Try to specify module to load class from using '{CLASS@module}class_name'")
	RuntimeException unableToLoadPasswordClass(@Cause Throwable t, String classToLoad);

	@Message(id = 144, value = "Trying to load null or empty class")
	RuntimeException loadingNullorEmptyClass();

	@Message(id = 146, value = "The value for option %s is not at least %s bytes in length per NIST SP 800-132 recommendations.")
	String saltTooShortMessage(String optionName, int minSaltLength);

	@Message(id = 147, value = "The value for option %s does not match the cryptographic key length of %s bits.")
	String ivLengthDoesNotMatchBlockSizeMessage(String optionName, int keyLength);

	@Message(id = 148, value = "The value for option %s is not at least %s per NIST SP 800-132 recommendations.")
	String iterationCountTooLowMessage(String optionName, int keyLength);

	@Message(id = 149, value = "Unable to initialize secure cache for password commands")
	RuntimeException unableToInitializePasswordCache(@Cause Throwable t);

	@Message(id = 150, value = "Unable to retrieve the password for key %s")
	RuntimeException unableToRetrieveCachedPassword(@Cause Throwable t, String key);

	@Message(id = 151, value = "Unable to store the password for key %s")
	RuntimeException unableToStorePasswordInCache(@Cause Throwable t, String key);

	@Message(id = 152, value = "Unable to digest the password key")
	RuntimeException unableToDigestPasswordKey(@Cause Throwable t);
}
