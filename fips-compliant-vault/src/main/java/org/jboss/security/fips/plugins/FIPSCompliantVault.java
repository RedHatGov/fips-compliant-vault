/**
 * 
 */
package org.jboss.security.fips.plugins;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.jboss.logging.Logger;
import org.jboss.security.Base64Utils;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.util.Password;

/**
 * An instance of {@link SecurityVault} that uses the Mozilla Network Security
 * Services for Java (JSS) Java Cryptography Architecture (JCA) provider to mask
 * passwords using FIPS 140-2 compliant cryptography.
 * 
 * The following system property is expected to be defined in the Red Hat JBoss
 * Enterprise Application Platform (EAP) configuration file:
 * <ul>
 * <li>fips.vault.path: fully-qualified path to the Mozilla NSS database
 * directory</li>
 * </ul>
 * The following options are expected in the {@link SecurityVault#init(Map)}
 * call:
 * <ul>
 * <li>TOKEN_PIN: Masked NSS cryptographic token PIN. Has to be prepended with
 * the literal 'MASK-' followed by a base-64 encoded value</li>
 * <li>SALT: salt of the masked token PIN. This should be a randomly generated
 * 128 bit long value encoded using base-64</li>
 * <li>IV: initialization vector used to mask the token PIN. This should be a 64
 * bit long value encoded using base-64.</li>
 * </ul>
 * 
 * @author rlucente@redhat.com
 * @since Sep 20, 2014
 */
public class FIPSCompliantVault implements SecurityVault {

	private static final Logger LOGGER = Logger
			.getLogger(FIPSCompliantVault.class);

	// admin key constants
	private static final String ADMIN_KEY_VAULTBLOCK = "admin";
	private static final String ADMIN_KEY_ATTRIBUTE = "key";

	private static final String ADMIN_KEY_TYPE = "AES";
	private static final String ADMIN_KEY_WRAP_ALG = "RSA";

	// password masking constants
	private static final int AES_KEY_LEN = 128;
	private static final String VAULT_CRYPTO_FULL_ALG = ADMIN_KEY_TYPE
			+ "/CBC/PKCS5Padding";

	// token pin mask parameters
	private static final String MASK_ALG_CRYPTO = "DESede";
	private static final String MASK_ALG_FULL = MASK_ALG_CRYPTO
			+ "/CBC/PKCS5Padding";

	// vault-option names and parsing constants
	private static final String IV = "IV";
	private static final String SALT = "SALT";
	private static final String MASKED_TOKEN_PIN = "TOKEN_PIN";
	private static final String MASKED_TOKEN_PREFIX = "MASK-";

	// property for directory containing the Mozilla NSS database files
	private static final String NSSDB_PATH_PROPERTY_NAME = "fips.vault.path";

	// NIST Special Publication 800-132 recommendations for PBKDF2 algorithm
	private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
	private static final int PBE_MIN_ITERATION_COUNT = 1000;
	private static final int PBE_SALT_MIN_LEN = 128 / 8;

	// fixed string to seed PBE, see http://xkcd.com/221/
	private static final String PBE_SEED = "areallylongthrowawaystringthatdoesnotmatter";

	// pseudo-random number generator
	private static final String PRNG_ALGORITHM = "pkcs11prng";

	// vault data file
	private static final String VAULT_CONTENT_FILE = "vault.dat";

	/*
	 * Static initializer to enable the Mozilla-JSS JCA provider and load the
	 * small native library to expose the Mozilla NSS PBKDF2 function. This
	 * class needs to be placed within a module in EAP so that it's loaded once
	 * by the modular class loader.
	 */
	static {
		String nssdbPath = System.getProperty(NSSDB_PATH_PROPERTY_NAME);

		try {
			CryptoManager.initialize(nssdbPath);
			System.loadLibrary("nss_pbkdf2");
		} catch (Throwable t) {
			LOGGER.fatal("Unable to initialize the Mozilla JCA provider.  "
					+ "Please verify that the system property '"
					+ NSSDB_PATH_PROPERTY_NAME
					+ "' is defined and that the Mozilla "
					+ "NSS database files exist in that directory and "
					+ "they are initialized.");
			throw new RuntimeException(t);
		}
	}

	// key used to decrypt the vault content
	private SecretKey adminKey = null;

	// get JCA providers by name regardless of the preferred JVM order
	private Provider fipsProvider = Security.getProvider("Mozilla-JSS");
	private Provider sunJCEProvider = Security.getProvider("SunJCE");

	// the cryptographic token
	private CryptoToken fipsToken;

	// pseudo-random number generator
	private SecureRandom random;

	// the vault data
	private FIPSCompliantVaultData vaultContent = null;
	private boolean finishedInit = false;

	// fully qualified path of vault directory
	private String vaultDir;

	/**
	 * @see org.jboss.security.vault.SecurityVault#exists(String, String)
	 */
	@Override
	public boolean exists(String vaultBlock, String attributeName)
			throws SecurityVaultException {
		return vaultContent.getVaultData(vaultBlock, attributeName) != null;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#handshake(java.util.Map)
	 */
	@Override
	public byte[] handshake(Map<String, Object> handshakeOptions)
			throws SecurityVaultException {
		// doesn't do anything meaningful in this implementation
		return new byte[PBE_SALT_MIN_LEN];
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#init(java.util.Map)
	 */
	@Override
	public void init(Map<String, Object> options) throws SecurityVaultException {
		if (options == null || options.isEmpty())
			logErrorAndThrowSVE("required options missing or empty");

		String maskedTokenPin = (String) options.get(MASKED_TOKEN_PIN);
		if (maskedTokenPin == null)
			logErrorAndThrowSVE("missing required option " + MASKED_TOKEN_PIN);

		if (maskedTokenPin.startsWith(MASKED_TOKEN_PREFIX) == false)
			logErrorAndThrowSVE("invalid masked token pin '" + maskedTokenPin
					+ "'");

		String saltOptVal = (String) options.get(SALT);
		if (saltOptVal == null)
			logErrorAndThrowSVE("missing required option " + SALT);

		byte[] salt = null;
		try {
			salt = Base64Utils.fromb64(saltOptVal);
		} catch (NumberFormatException nfe) {
			logErrorAndThrowSVE(
					"salt is not a valid base-64 encoded byte array", nfe);
		}

		if (salt.length < PBE_SALT_MIN_LEN)
			logErrorAndThrowSVE("salt must be at least " + PBE_SALT_MIN_LEN
					+ " bytes in length");

		String ivOptVal = (String) options.get(IV);
		if (ivOptVal == null)
			logErrorAndThrowSVE("missing required option " + IV);

		byte[] iv = null;
		try {
			iv = Base64Utils.fromb64(ivOptVal);
		} catch (NumberFormatException nfe) {
			logErrorAndThrowSVE(
					"initialization vector is not a valid base-64 encoded byte array",
					nfe);
		}

		if (iv.length != DESKeySpec.DES_KEY_LEN)
			logErrorAndThrowSVE("initialization vector must be "
					+ DESKeySpec.DES_KEY_LEN + " bytes in length");

		Password tokenPin = null;
		SecretKey maskKey = null;
		try {
			// derive the key to unmask the token PIN
			maskKey = deriveMaskKey(salt);

			// log into the cryptographic token
			tokenPin = unmaskTokenPin(maskedTokenPin, maskKey, iv,
					sunJCEProvider);
			fipsToken = CryptoManager.getInstance()
					.getInternalKeyStorageToken();
			fipsToken.login(tokenPin);

			// at this point, FIPS-compliant cryptography ONLY!
			sunJCEProvider = null;
		} catch (Exception e) {
			logErrorAndThrowSVE("failed to log into cryptographic token", e);
		}

		/*
		 * Because of the chicken and egg problem, we have to use the SunJCE
		 * provider first to unmask the token PIN since FIPS compliant
		 * cryptography isn't enabled until you log into the token. Now we redo
		 * unmasking the token pin using FIPS compliant cryptography only
		 */
		try {
			maskKey = fipsDeriveMaskKey(salt);
			Password fipsTokenPin = unmaskTokenPin(maskedTokenPin, maskKey, iv,
					fipsProvider);

			// logout so we can then login using the fips unmasked token pin
			fipsToken.logout();

			// make sure we get the same result, validating what we did with
			// SunJCE
			if (!fipsTokenPin.equals(tokenPin))
				logErrorAndThrowSVE("unmasked token PIN using FIPS provider"
						+ " does not match token PIN using SunJCE provider");

			// clear the prior pin and
			tokenPin.clear();
			tokenPin = fipsTokenPin;
			fipsToken.login(tokenPin);

			// set the random source
			random = SecureRandom.getInstance(PRNG_ALGORITHM, fipsProvider);
		} catch (Exception e) {
			logErrorAndThrowSVE(
					"failed to log into cryptographic token using FIPS derived key",
					e);
		}

		// clear the token pin since we don't need it anymore
		tokenPin.clear();

		// read raw vault content
		readVaultContent();

		// extract the admin key
		adminKey = getAdminKey();
		if (adminKey == null) {
			logErrorAndThrowSVE("failed to get admin key from vault");
		}

		LOGGER.info("FIPS compliant password vault successfully initialized");

		finishedInit = true;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#isInitialized()
	 */
	@Override
	public boolean isInitialized() {
		return finishedInit;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#keyList()
	 */
	@Override
	public Set<String> keyList() throws SecurityVaultException {
		return vaultContent.getVaultDataKeys();
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#remove(java.lang.String,
	 * java.lang.String, byte[])
	 */
	@Override
	public boolean remove(String vaultBlock, String attributeName,
			byte[] sharedKey) throws SecurityVaultException {
		try {
			vaultContent.deleteVaultData(vaultBlock, attributeName);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#retrieve(java.lang.String,
	 * java.lang.String, byte[])
	 */
	@Override
	public char[] retrieve(String vaultBlock, String attributeName,
			byte[] sharedKey) throws SecurityVaultException {
		// make sure map key is valid
		if (vaultBlock == null || vaultBlock.isEmpty())
			logErrorAndThrowSVE("vault block parameter is null or empty");

		if (attributeName == null || attributeName.isEmpty())
			logErrorAndThrowSVE("attribute name parameter is null or empty");

		char[] vaultValue = new char[0];

		// read the raw byte array value matching the given key
		byte[] rawBytes = vaultContent.getVaultData(vaultBlock, attributeName);

		if (rawBytes != null) {
			ByteBuffer rawBuffer = ByteBuffer.wrap(rawBytes);

			// extract the initialization vector
			byte[] iv = new byte[AES_KEY_LEN];
			rawBuffer.get(iv);

			// extract the cipher text
			byte[] ciphertext = new byte[rawBuffer.remaining()];
			rawBuffer.get(ciphertext);

			// decrypt the vault value using the admin key
			byte[] plaintext = null;
			try {
				Cipher cipher = Cipher.getInstance(VAULT_CRYPTO_FULL_ALG,
						fipsProvider);
				cipher.init(Cipher.DECRYPT_MODE, adminKey, new IvParameterSpec(
						iv));
				plaintext = cipher.doFinal(ciphertext);
			} catch (Exception e) {
				logErrorAndThrowSVE("unable to decrypt vault value for '"
						+ vaultBlock
						+ FIPSCompliantVaultData.PROPERTY_SEPARATOR
						+ attributeName + "'");
			}

			// convert the plain text
			if (plaintext != null) {
				vaultValue = Charset.forName("UTF-8")
						.decode(ByteBuffer.wrap(plaintext)).array();

				// clear the plain text data
				Password.wipeBytes(plaintext);
			}
		}

		return vaultValue;
	}

	/*
	 * @see org.jboss.security.vault.SecurityVault#store(java.lang.String,
	 * java.lang.String, char[], byte[])
	 * 
	 * @param sharedKey is ignored for this implementation
	 */
	@Override
	public void store(String vaultBlock, String attributeName,
			char[] attributeValue, byte[] sharedKey)
			throws SecurityVaultException {
		if (vaultBlock == null || vaultBlock.isEmpty()) {
			String msg = "vault block '" + vaultBlock + "' is not valid";
			LOGGER.error(msg);
			throw new SecurityVaultException(msg);
		}

		if (attributeName == null || attributeName.isEmpty()) {
			String msg = "attribute name '" + attributeName + "' is not valid";
			LOGGER.error(msg);
			throw new SecurityVaultException(msg);
		}

		// generate a random initialization vector
		byte[] iv = new byte[AES_KEY_LEN];
		random.nextBytes(iv);

		// encrypt the given attribute value using the admin key
		byte[] plaintext = Charset.forName("UTF-8")
				.encode(CharBuffer.wrap(attributeValue)).array();

		byte[] ciphertext = new byte[0];
		try {
			Cipher cipher = Cipher.getInstance(VAULT_CRYPTO_FULL_ALG,
					fipsProvider);
			cipher.init(Cipher.ENCRYPT_MODE, adminKey, new IvParameterSpec(iv));
			ciphertext = cipher.doFinal(plaintext);
		} catch (Exception e) {
			String msg = "unable to encrypt vault entry";
			LOGGER.error(msg);
			throw new SecurityVaultException(msg);
		}

		Password.wipeChars(attributeValue);
		Password.wipeBytes(plaintext);

		// concatenate the iv and ciphertext and then store as one byte array in
		// the vault
		ByteBuffer rawBuffer = ByteBuffer.wrap(new byte[iv.length
				+ ciphertext.length]);
		rawBuffer.put(iv);
		rawBuffer.put(ciphertext);

		vaultContent.addVaultData(vaultBlock, attributeName, rawBuffer.array());

		try {
			writeVaultData();
		} catch (IOException e) {
			String msg = "unable to write the vault data";
			LOGGER.error(msg);
			throw new SecurityVaultException(msg);
		}
	}

	/**
	 * Derive a password-based encryption key to unmask the token PIN for the
	 * NSS database. The SunJCE provider is used here because 1) we can't use
	 * the Mozilla-JSS JCA provider crytographic functions until we've logged
	 * into the cryptographic token and 2) the Mozilla-JSS JCA provider does not
	 * expose the NSS implementation of PBKDF2 from PKCS #5, v2.0.
	 * 
	 * This is all a bit of overkill since we're using a fixed string for the
	 * passphrase and a saved salt value to generate the key. We effectively
	 * have zero entropy, but it obfuscates the cryptographic token PIN.
	 * 
	 * @return password-based encryption key
	 * @throws Exception
	 */
	private SecretKey deriveMaskKey(byte[] salt) throws Exception {
		// fixed string to seed PBE, see http://xkcd.com/221/
		char[] passphrase = PBE_SEED.toCharArray();

		// Derive the key that will be used to mask the password. The same key
		// will be generated as long as the parameters are the same
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM,
				sunJCEProvider);
		PBEKeySpec pbeSpec = new PBEKeySpec(passphrase, salt,
				PBE_MIN_ITERATION_COUNT, DESedeKeySpec.DES_EDE_KEY_LEN * 8);
		SecretKey pbeKey = factory.generateSecret(pbeSpec);

		// convert the generated key to 3DES since that will be used to mask the
		// password
		factory = SecretKeyFactory.getInstance(MASK_ALG_CRYPTO, sunJCEProvider);
		KeySpec keySpec = new DESedeKeySpec(pbeKey.getEncoded());
		return factory.generateSecret(keySpec);
	}

	/**
	 * Use the FIPS compliant library to derive a password-based encryption key
	 * to unmask the token PIN for the NSS database. This leverages the Mozilla
	 * NSS implementation of PBKDF2 from PKCS #5, v2.0.
	 * 
	 * Again, this is all a bit of overkill since we're using a fixed string for
	 * the passphrase and a saved salt value to generate the key. We effectively
	 * have zero entropy, but it obfuscates the cryptographic token PIN.
	 * 
	 * @return password-based encryption key
	 * @throws Exception
	 */
	private SecretKey fipsDeriveMaskKey(byte[] salt) throws Exception {
		// fixed string to seed PBE, see http://xkcd.com/221/
		byte[] passphrase = PBE_SEED.getBytes("UTF-8");

		// Derive the key that will be used to mask the password. The same key
		// will be generated as long as the parameters are the same
		SymmetricKey symKey = deriveKeyFromPassword(fipsToken, passphrase,
				salt, PBE_MIN_ITERATION_COUNT,
				DESedeKeySpec.DES_EDE_KEY_LEN * 8);
		return new SecretKeyFacade(symKey);
	}

	/**
	 * Use the certificate private key in the FIPS token crypto store to unwrap
	 * the admin key.
	 * 
	 * @return SecretKey stored in vault file or null if no such SecretKey
	 *         exists
	 */
	private SecretKey getAdminKey() {
		// read the byte array for the wrapped key
		byte[] wrappedKey = vaultContent.getVaultData(ADMIN_KEY_VAULTBLOCK,
				ADMIN_KEY_ATTRIBUTE);

		SecretKey unwrappedKey = null;

		if (wrappedKey != null) {
			try {
				// get the private key to unwrap the admin key
				CryptoStore store = fipsToken.getCryptoStore();
				PrivateKey priv = store.getPrivateKeys()[0];

				// unwrap the admin key using the cert priv key
				Cipher cipher = Cipher.getInstance(ADMIN_KEY_WRAP_ALG,
						fipsProvider);
				cipher.init(Cipher.UNWRAP_MODE, priv);
				unwrappedKey = (SecretKey) cipher.unwrap(wrappedKey,
						ADMIN_KEY_TYPE, Cipher.SECRET_KEY);
			} catch (Exception e) {
				LOGGER.error("failed to unwrap the admin key", e);
			}
		}

		return unwrappedKey;
	}

	/**
	 * @param msg
	 * @throws SecurityVaultException
	 */
	private void logErrorAndThrowSVE(String msg) throws SecurityVaultException {
		LOGGER.error(msg);
		throw new SecurityVaultException(msg);
	}

	/**
	 * @param msg
	 * @param t
	 * @throws SecurityVaultException
	 */
	private void logErrorAndThrowSVE(String msg, Throwable t)
			throws SecurityVaultException {
		LOGGER.error(msg, t);
		throw new SecurityVaultException(msg, t);
	}

	/**
	 * quietly close the stream
	 * 
	 * @param stream
	 */
	private void quietlyClose(Closeable stream) {
		try {
			if (stream != null) {
				stream.close();
			}
		} catch (Exception e) {
		}
	}

	/**
	 * Reads the raw content of the vault file.
	 * 
	 * @throws SecurityVaultException
	 *             if the vault file does not exist or is not readable
	 */
	private void readVaultContent() throws SecurityVaultException {
		try {
			// set the vault path
			vaultDir = System.getProperty(NSSDB_PATH_PROPERTY_NAME);
			if (!vaultDir.endsWith(System.getProperty(File.pathSeparator))) {
				vaultDir = vaultDir + File.pathSeparator;
			}

			if (vaultFileExists() == false) {
				String msg = "the vault file does not exist or is not readable";
				LOGGER.error(msg);
				throw new SecurityVaultException(msg);
			}

			// read the vault content
			FileInputStream fis = null;
			ObjectInputStream ois = null;
			try {
				fis = new FileInputStream(vaultDir + VAULT_CONTENT_FILE);
				ois = new ObjectInputStream(fis);
				vaultContent = (FIPSCompliantVaultData) ois.readObject();
			} finally {
				quietlyClose(fis);
				quietlyClose(ois);
			}
		} catch (Exception e) {
			throw new SecurityVaultException(e);
		}
	}

	/**
	 * Unmask the NSS token password.
	 * 
	 * @param maskedTokenPin
	 * @param maskKey
	 * @param tokenPinIv
	 * @param provider
	 * @return
	 * @throws Exception
	 */
	private Password unmaskTokenPin(String maskedTokenPin, SecretKey maskKey,
			byte[] tokenPinIv, Provider provider) throws Exception {
		// get the encrypted token pin
		maskedTokenPin = maskedTokenPin.substring(MASKED_TOKEN_PREFIX.length());
		byte[] ciphertext = Base64Utils.fromb64(maskedTokenPin);

		// decrypt the token pin using the derived secret key
		Cipher cipher = Cipher.getInstance(MASK_ALG_FULL, provider);
		cipher.init(Cipher.DECRYPT_MODE, maskKey, new IvParameterSpec(
				tokenPinIv));
		byte[] plaintext = cipher.doFinal(ciphertext);

		// convert byte array to char array
		Charset cs = Charset.forName("UTF-8");
		char[] password = cs.decode(ByteBuffer.wrap(plaintext)).array();

		// convert so we can log into the token
		Password tokenPin = new Password(password);

		// wipe the intermediate results from memory
		Password.wipeBytes(plaintext);
		Password.wipeChars(password);

		return tokenPin;
	}

	/**
	 * @return true if file exists and readable, false otherwise
	 */
	private boolean vaultFileExists() {
		File vaultPath = new File(vaultDir);

		if (vaultPath.exists()) {
			File file = new File(vaultDir + VAULT_CONTENT_FILE);
			return file != null && file.exists() && file.canRead();
		}

		return false;
	}

	/**
	 * Write the vault data content to the vault file
	 * 
	 * @throws IOException
	 */
	private void writeVaultData() throws IOException {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream(vaultDir + VAULT_CONTENT_FILE);
			oos = new ObjectOutputStream(fos);
			oos.writeObject(vaultContent);
		} finally {
			quietlyClose(oos);
			quietlyClose(fos);
		}
	}

	/**
	 * Native method that exposes the Mozilla NSS implementation of PKCS#5
	 * PBKDF2 password-based encryption
	 * 
	 * @param token
	 * @param password
	 * @param salt
	 * @param iterationCount
	 * @param keyLength
	 * @return symmetric 3des key
	 */
	static private native SymmetricKey deriveKeyFromPassword(CryptoToken token,
			byte[] password, byte[] salt, int iterationCount, int keyLength);
}
