package org.jboss.security.fips.utils;

import java.io.Console;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.encoders.Base64;

public class CryptoUtil {
	private static final String DEFAULT_DRBG_NAME = "DEFAULT";
	public static final String PROVIDER_NAME = "BCFIPS";

	// keystore password mask parameters
	private static final String MASK_ALG_NAME = "AES";
	public static final int MASK_KEY_STRENGTH = 128; // in bits
	private static final String MASK_ALG_FULL = MASK_ALG_NAME + "/CBC/PKCS5Padding";

	// general key parameters
	private static final String ALG_NAME = "AES";
	public static final int KEY_STRENGTH = 128; // in bits
	public static final String ALG_FULL = MASK_ALG_NAME + "/CBC/PKCS5Padding";

	// NIST Special Publication 800-132 recommendations for PBKDF2 algorithm
	private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA512";
	public static final int PBE_MIN_ITERATION_COUNT = 1000;
	public static final int PBE_SALT_MIN_LEN = 128 / 8; // in bytes

	// fixed "random" string to seed PBE, see http://xkcd.com/221/
	private static final String PBE_SEED = "JDAtznrxbRzxQdOERMtSRqSS0izyctfu8EUt5MR2DCColbjlTBlTbUvFVwdX";

	// approved message digest algorithm
	private static final String MSG_DIGEST_ALG = "SHA-256";

	static {
		Security.addProvider(new BouncyCastleFipsProvider());
	}

	/**
	 * Decrypt the given base-64 encoded string
	 * 
	 * @param key
	 *            key used to decrypt
	 * @param iv
	 *            the initialization vector
	 * @param b64cipher
	 *            the encrypted data as a base-64 encoded string
	 * @return the decrypted char array
	 */
	public static char[] decryptB64(SecretKey key, byte[] iv, String b64cipher) throws GeneralSecurityException {
		byte[] ciphertext = null;
		try {
			ciphertext = Base64.decode(b64cipher);
			return decrypt(key, iv, ciphertext);
		} finally {
			// clear sensitive data
			Arrays.fill(ciphertext, (byte) 0);
		}
	}

	/**
	 * Decrypt the given data
	 * 
	 * @param key
	 *            key used to decrypt
	 * @param iv
	 *            the initialization vector
	 * @param ciphertext
	 *            the encrypted data as a byte array
	 * @return the decrypted char array
	 */
	public static char[] decrypt(SecretKey key, byte[] iv, byte[] ciphertext) throws GeneralSecurityException {
		byte[] plaintext = decrypt(ALG_FULL, key, iv, ciphertext);
		char[] attrValue = Charset.forName("UTF-8").decode(ByteBuffer.wrap(plaintext)).array();

		// clear sensitive data
		Arrays.fill(plaintext, (byte) 0);

		return attrValue;
	}

	/**
	 * Derive a password-based encryption key to mask/unmask the keystore
	 * password. This is all a bit of overkill since we're using a fixed string
	 * for the passphrase and a saved salt value to generate the key. We
	 * effectively have zero entropy, but it obfuscates the keystore password.
	 * 
	 * @param salt
	 *            an array of bytes to be used as salt when generating the key
	 * @param iterationCount
	 *            the number of iterations to use when generating the key
	 * @return password-based encryption key matching the mask algorithm
	 * @throws GeneralSecurityException
	 */
	public static SecretKey deriveMaskKey(byte[] salt, int iterationCount) throws GeneralSecurityException {
		// convert fixed pass phrase to array
		char[] passphrase = PBE_SEED.toCharArray();

		// Derive the key that will be used to mask the password. The same key
		// will be generated as long as the parameters are the same
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM, PROVIDER_NAME);
		PBEKeySpec keySpec = new PBEKeySpec(passphrase, salt, iterationCount, MASK_KEY_STRENGTH);
		SecretKey rawCipherKey = factory.generateSecret(keySpec);
		return new SecretKeySpec(rawCipherKey.getEncoded(), MASK_ALG_NAME);
	}

	/**
	 * Calculate a base-64 encoded digest for the given data
	 * 
	 * @param data
	 *            the string to be digested and encoded
	 * @return the base-64 encoded digest
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws UnsupportedEncodingException
	 */
	public static String digest(String data) throws GeneralSecurityException, UnsupportedEncodingException {
		MessageDigest digest = MessageDigest.getInstance(MSG_DIGEST_ALG, PROVIDER_NAME);
		return Base64.toBase64String(digest.digest(data.getBytes("UTF-8")));
	}

	/**
	 * Encrypt the given data
	 * 
	 * @param key
	 *            key used to decrypt
	 * @param iv
	 *            the initialization vector
	 * @param b64cipher
	 *            the encrypted data as a base-64 encoded string
	 * @return the decrypted char array
	 */
	public static String encryptB64(SecretKey key, byte[] iv, char[] value) throws GeneralSecurityException {
		byte[] ciphertext = null;
		try {
			ciphertext = encrypt(key, iv, value);
			return Base64.toBase64String(ciphertext);
		} finally {
			Arrays.fill(ciphertext, (byte) 0);
		}
	}

	/**
	 * Encrypt the attribute value in the vault
	 * 
	 * @param key
	 *            key used to encrypt the attribute value
	 * @param iv
	 *            the initialization vector
	 * @param value
	 *            the attribute value as a char array
	 * @return the encrypted value as a byte array
	 */
	public static byte[] encrypt(SecretKey key, byte[] iv, char[] value) throws GeneralSecurityException {
		byte[] plaintext = Charset.forName("UTF-8").encode(CharBuffer.wrap(value)).array();
		byte[] ciphertext = encrypt(ALG_FULL, key, iv, plaintext);

		// clear sensitive data
		Arrays.fill(plaintext, (byte) 0);

		return ciphertext;
	}

	/**
	 * Generates the admin key to encrypt/decrypt password attribute values
	 * 
	 * @return secret key to encrypt/decrypt password attribute values
	 * @throws GeneralSecurityException
	 */
	public static SecretKey generateKey() throws GeneralSecurityException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(ALG_NAME, PROVIDER_NAME);
		keyGenerator.init(KEY_STRENGTH);
		return keyGenerator.generateKey();
	}

	/**
	 * Generates a random sequence of bytes of the given length. This is used
	 * for initialization vectors, salt values, and cryptographic keys
	 * 
	 * @param length
	 *            the length (in bytes) desired
	 * @return a byte array of random bits matching the desired length in bytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] genRandomBytes(int length) throws NoSuchAlgorithmException, NoSuchProviderException {
		SecureRandom random = SecureRandom.getInstance(DEFAULT_DRBG_NAME, PROVIDER_NAME);
		byte[] data = new byte[length];
		random.nextBytes(data);
		return data;
	}

	/**
	 * Mask the keystore password using the derived mask key and given
	 * initialization vector.
	 * 
	 * @param storePass
	 *            the keystore password
	 * @param maskKey
	 *            the key to mask the password
	 * @param iv
	 *            the initialization vector
	 * @return a base-64 encoded string of the encrypted keystore password
	 * @throws Exception
	 */
	public static String maskKeystorePassword(char[] storePass, SecretKey maskKey, byte[] iv) throws Exception {
		// convert keystore password to bytes without using String
		byte[] plaintext = Charset.forName("UTF-8").encode(CharBuffer.wrap(storePass)).array();

		// mask the key
		byte[] ciphertext = encrypt(MASK_ALG_FULL, maskKey, iv, plaintext);
		String resultB64 = Base64.toBase64String(ciphertext);

		// clear sensitive data
		Arrays.fill(plaintext, (byte) 0);
		Arrays.fill(ciphertext, (byte) 0);

		// return ciphertext as base64 string
		return resultB64;
	}

	/**
	 * Read sensitive string as a character array with the given prompt. This
	 * forces the user to enter the data twice to confirm that they match.
	 * 
	 * @param prompt
	 *            the prompt for the desired value
	 * @return the sensitive data as a character array
	 */
	public static char[] readSensitiveString(String prompt) {
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

	/**
	 * Unmask the encrypted keystore password using the derived mask key and
	 * given initialization vector.
	 * 
	 * @param maskedStorePass
	 *            the encrypted keystore password
	 * @param maskKey
	 *            the key to mask the password
	 * @param iv
	 *            the initialization vector
	 * @return the plaintext keystore password as a char array
	 * @throws Exception
	 */
	public static char[] unmaskKeystorePassword(String maskedStorePass, SecretKey maskKey, byte[] iv) throws Exception {
		byte[] ciphertext = Base64.decode(maskedStorePass);

		// unmask the key
		byte[] plaintext = decrypt(MASK_ALG_FULL, maskKey, iv, ciphertext);
		char[] storePass = Charset.forName("UTF-8").decode(ByteBuffer.wrap(plaintext)).array();

		// clear sensitive data
		Arrays.fill(plaintext, (byte) 0);
		Arrays.fill(ciphertext, (byte) 0);

		// return ciphertext
		return storePass;
	}

	/**
	 * Decrypt the given ciphertext using the given parameters
	 * 
	 * @param fullCryptoAlgo
	 *            the fully specified cryptographic algorithm including the
	 *            algorithm, block mode, and padding
	 * @param key
	 *            the secret key matching the above algorithm specification
	 * @param iv
	 *            the initialization vector to use
	 * @param ciphertext
	 *            the data to be decrypted
	 * @return the plaintext as an array of bytes
	 * @throws GeneralSecurityException
	 */
	private static byte[] decrypt(String fullCryptoAlgo, SecretKey key, byte[] iv, byte[] ciphertext)
			throws GeneralSecurityException {
		return doCrypto(Cipher.DECRYPT_MODE, fullCryptoAlgo, key, iv, ciphertext);
	}

	/**
	 * Perform desired cryptographic operation
	 * 
	 * @param mode
	 *            either Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE
	 * @param fullCryptoAlgo
	 *            the fully specified cryptographic algorithm including the
	 *            algorithm, block mode, and padding
	 * @param key
	 *            the secret key matching the above algorithm specification
	 * @param iv
	 *            the initialization vector to use
	 * @param data
	 *            the data to be either decrypted or encrypted
	 * @return result as array of bytes. For encryption, the data will be padded
	 *         to a full block size matching the desired algorithm block size
	 * @throws GeneralSecurityException
	 */
	private static byte[] doCrypto(int mode, String fullCryptoAlgo, SecretKey key, byte[] iv, byte[] data)
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(fullCryptoAlgo, PROVIDER_NAME);
		cipher.init(mode, key, new IvParameterSpec(iv));
		return cipher.doFinal(data);
	}

	/**
	 * Encrypt the given plaintext using the given parameters
	 *
	 * @param fullCryptoAlgo
	 *            the fully specified cryptographic algorithm including the
	 *            algorithm, block mode, and padding
	 * @param key
	 *            the secret key matching the above algorithm specification
	 * @param iv
	 *            the initialization vector to use
	 * @param plaintext
	 *            the data to be encrypted
	 * @return the ciphertext as an array of full blocks (with padding if
	 *         necessary)
	 * @throws GeneralSecurityException
	 */
	private static byte[] encrypt(String fullCryptoAlgo, SecretKey key, byte[] iv, byte[] plaintext)
			throws GeneralSecurityException {
		return doCrypto(Cipher.ENCRYPT_MODE, fullCryptoAlgo, key, iv, plaintext);
	}
}
