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

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.jboss.logging.Logger;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback.GiveUpException;

/**
 * Utility functions for FIPS compliant vault cryptography.
 * 
 * @author Rich Lucente
 * @since Oct 10, 2014
 */
public class FIPSCryptoUtil {
	private static final Logger LOGGER = Logger.getLogger(FIPSCryptoUtil.class);

	public static final String ADMIN_KEY_TYPE = "AES";
	private static final int ADMIN_KEY_LENGTH = 128;
	private static final String ADMIN_KEY_WRAP_ALG = "RSA";

	// password masking constants
	public static final int AES_KEY_LEN = 128;
	public static final String VAULT_CRYPTO_FULL_ALG = "AES/CBC/PKCS5Padding";

	// token pin mask parameters
	private static final String MASK_ALG_CRYPTO = "DESede";
	private static final String MASK_ALG_FULL = MASK_ALG_CRYPTO
			+ "/CBC/PKCS5Padding";
	private static final int MASK_KEY_STRENGTH = 192;

	// NIST Special Publication 800-132 recommendations for PBKDF2 algorithm
	private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
	private static final int PBE_MIN_ITERATION_COUNT = 1000;
	public static final int PBE_SALT_MIN_LEN = 128 / 8;

	// fixed string to seed PBE, see http://xkcd.com/221/
	private static final String PBE_SEED = "areallylongthrowawaystringthatdoesnotmatter";

	// pseudo-random number generator
	public static final String PRNG_ALGORITHM = "pkcs11prng";

	// provider names
	public static final String FIPS_PROVIDER_NAME = "Mozilla-JSS";
	public static final String NONFIPS_PROVIDER_NAME = "SunJCE";

	// nickname for the vault pub/priv key pair
	private static final String VAULTCERT_NICKNAME = "vaultcert";

	/*
	 * Static initializer to load the small native library to expose the Mozilla
	 * NSS PBKDF2 function.
	 */
	static {
		try {
			System.loadLibrary("nss_pbkdf2");
		} catch (Throwable t) {
			LOGGER.fatal("Unable to load the JNI library for the PKCS #5, "
					+ "PBKDF v2 function.");
			throw new RuntimeException(t);
		}
	}

	/*
	 * Static initializer to kluge around a mismatch in the JSS and NSS
	 * implementations. In NSS, the file <pre>
	 * 
	 * @code nss/lib/softoken/pkcs11c.c
	 * 
	 * </pre> contains the function: <pre>
	 * 
	 * @code unsigned long sftk_MapKeySize(CK_KEY_TYPE keyType);
	 * 
	 * </pre> which requires that a key type of CKK_DES3 has a 24 byte (192 bit)
	 * key strength. This conflicts with a key validation check in JSS. The JSS
	 * file <pre>
	 * 
	 * @code jss/security/jss/org/mozilla/jss/crypto/EncryptionAlgorithm.java
	 * 
	 * <pre> instantiates several objects of itself that are added to an
	 * internal static list to define the valid list of algorithms including
	 * algorithm name, mode, padding, and key strength. For 3DES, only key
	 * strengths of 168 bits (21 bytes) are added to this list. For
	 * "DESede/CBC/PKCS5Padding", the actual values are: <pre>
	 * 
	 * @code public static final EncryptionAlgorithm DES3_CBC_PAD = new
	 * EncryptionAlgorithm(CKM_DES3_CBC_PAD, Alg.DESede, Mode.CBC,
	 * Padding.PKCS5, IVParameterSpecClasses, 8, null, 168); //no oid
	 * 
	 * </pre> If the key strength validation succeeds in NSS then it will fail
	 * in JSS and vice versa. As a work around to this, reflection is used to
	 * instantiate another instance of EncryptionAlgorithm that is added to the
	 * internal validation list to match the NSS 192 bit key strength for 3DES.
	 */
	public static class KludgeEncryptionAlgorithm extends EncryptionAlgorithm {
		KludgeEncryptionAlgorithm(Class<?>[] ivParamSpecs) {
			super(CKM_DES3_CBC_PAD, Alg.DESede, Mode.CBC, Padding.PKCS5,
					ivParamSpecs, 8 /* blockSize */, null /* no oid */, 192 /* keyStrength */);
		}
	}

	public static final EncryptionAlgorithm DES3_CBC_PAD_192;
	static {
		try {
			// get the static protected IVParameterSpecClasses array
			Field field = EncryptionAlgorithm.class
					.getDeclaredField("IVParameterSpecClasses");
			field.setAccessible(true);

			DES3_CBC_PAD_192 = new KludgeEncryptionAlgorithm(
					(Class[]) field.get(null)); // IVParameterSpecClasses
		} catch (Throwable t) {
			// Fatal since we won't be able to use 3DES FIPS compliant
			// encryption
			throw new RuntimeException(
					"Unable to use 3DES FIPS compliant encryption", t);
		}
	}

	/**
	 * Encrypt/decrypt given data.
	 * 
	 * @param modeNON_FIPS_PROVIDER_NAME
	 *            can be either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
	 * @param algorithm
	 *            specifies the key type, cryptographic mode, and padding
	 * @param symmetricKey
	 *            the symmetric cryptographic key
	 * @param iv
	 *            the initialization vector
	 * @param data
	 *            undergoing encrypt/decrypt operation
	 * @return result of cryptographic operation
	 * @throws Exception
	 */
	public static byte[] doCrypto(int mode, String algorithm,
			SecretKey symmetricKey, byte[] iv, byte[] data, Provider provider)
			throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm, provider);
		cipher.init(mode, symmetricKey, new IvParameterSpec(iv));
		return cipher.doFinal(data);
	}

	/**
	 * Generates an admin key used to mask vault items.
	 * 
	 * @return generated admin key
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateAdminKey() throws NoSuchAlgorithmException {
		Provider fipsProvider = Security.getProvider(FIPS_PROVIDER_NAME);
		SecureRandom random = SecureRandom.getInstance(PRNG_ALGORITHM,
				fipsProvider);

		KeyGenerator keyGen = KeyGenerator.getInstance(ADMIN_KEY_TYPE,
				fipsProvider);
		keyGen.init(ADMIN_KEY_LENGTH, random);
		return keyGen.generateKey();
	}

	/**
	 * Use the SunJCE provider to derive a password-based encryption key to
	 * mask/unmask the token PIN for the NSS database. The SunJCE provider is
	 * used here because 1) we can't use the Mozilla-JSS JCA provider
	 * crytographic functions until we've logged into the cryptographic token
	 * and 2) the Mozilla-JSS JCA provider does not expose the NSS
	 * implementation of PBKDF v2 from PKCS #5.
	 * 
	 * This is all a bit of overkill since we're using a fixed string for the
	 * passphrase and a saved salt value to generate the key. We effectively
	 * have zero entropy, but it obfuscates the cryptographic token PIN.
	 * 
	 * @return password-based encryption key
	 * @throws Exception
	 */
	public static SecretKey nonFipsDeriveMaskKey(byte[] salt) throws Exception {
		// fixed string to seed PBE, see http://xkcd.com/221/
		char[] passphrase = PBE_SEED.toCharArray();

		// Derive the key that will be used to mask the password. The same key
		// will be generated as long as the parameters are the same
		Provider sunJCEProvider = Security.getProvider(NONFIPS_PROVIDER_NAME);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM,
				sunJCEProvider);
		PBEKeySpec pbeSpec = new PBEKeySpec(passphrase, salt,
				PBE_MIN_ITERATION_COUNT, MASK_KEY_STRENGTH);
		SecretKey pbeKey = factory.generateSecret(pbeSpec);

		// convert the generated key to 3DES since that will be used to mask the
		// password
		factory = SecretKeyFactory.getInstance(MASK_ALG_CRYPTO, sunJCEProvider);
		KeySpec keySpec = new DESedeKeySpec(pbeKey.getEncoded());
		return factory.generateSecret(keySpec);
	}

	/**
	 * Use the FIPS compliant library to derive a password-based encryption key
	 * to mask/unmask the token PIN for the NSS database. This leverages the
	 * Mozilla NSS implementation of PBKDF v2 from PKCS #5.
	 * 
	 * Again, this is all a bit of overkill since we're using a fixed string for
	 * the passphrase and a saved salt value to generate the key. We effectively
	 * have zero entropy, but it obfuscates the cryptographic token PIN.
	 * 
	 * @return password-based encryption key
	 * @throws Exception
	 */
	public static SecretKey fipsDeriveMaskKey(CryptoToken fipsToken, byte[] salt)
			throws Exception {
		// fixed string to seed PBE, see http://xkcd.com/221/
		byte[] passphrase = PBE_SEED.getBytes("UTF-8");

		// Derive the key that will be used to mask the password. The same key
		// will be generated as long as the parameters are the same
		SymmetricKey symKey = deriveKeyFromPassword(fipsToken, passphrase,
				salt, PBE_MIN_ITERATION_COUNT, MASK_KEY_STRENGTH);
		return new SecretKeyFacade(symKey);
	}

	/**
	 * Wrap the admin key using the certificate public key in the FIPS token
	 * crypto store.
	 * 
	 * @return wrapped key
	 */
	public static byte[] wrapKey(CryptoToken fipsToken, SecretKey adminKey) {
		byte[] wrappedKey = new byte[0];
		Provider fipsProvider = Security.getProvider(FIPS_PROVIDER_NAME);

		if (adminKey != null) {
			try {
				// get the public key to wrap the admin key
				CryptoStore store = fipsToken.getCryptoStore();
                                X509Certificate cert = findVaultCert(store);
                                PublicKey pub = cert.getPublicKey();

				// wrap the key using the cert public key
				wrappedKey = doWrapKey(pub, fipsProvider, adminKey);
			} catch (Exception e) {
				LOGGER.error("failed to wrap the key", e);
			}
		}

		return wrappedKey;
	}

	/**
	 * Use the certificate private key in the FIPS token crypto store to unwrap
	 * the admin key.
	 * 
	 * @return SecretKey stored in vault file or null if no such SecretKey
	 *         exists
	 */
	public static SecretKey unwrapKey(CryptoToken fipsToken, byte[] wrappedKey) {
		SecretKey unwrappedKey = null;
		Provider fipsProvider = Security.getProvider(FIPS_PROVIDER_NAME);

		if (wrappedKey != null) {
			try {
				// get the private key to unwrap the admin key
				CryptoStore store = fipsToken.getCryptoStore();
				int privIdx = findVaultPrivKeyIndex(store, fipsProvider);
				PrivateKey priv = store.getPrivateKeys()[privIdx];

				// unwrap the admin key using the cert priv key
				unwrappedKey = doUnwrapKey(priv, fipsProvider, wrappedKey);
			} catch (Exception e) {
				LOGGER.error("failed to unwrap the key", e);
			}
		}

		return unwrappedKey;
	}

	/**
	 * Mask the NSS token password using the Mozilla JSS provider.
	 */
	public static byte[] maskTokenPin(Password tokenPin, SecretKey maskKey,
			byte[] tokenPinIv) throws Exception {
		Provider fipsProvider = Security.getProvider(FIPS_PROVIDER_NAME);

		// convert char array to byte array
		Charset cs = Charset.forName("UTF-8");
		byte[] plaintext = cs.encode(CharBuffer.wrap(tokenPin.getChars()))
				.array();

		// encrypt the token pin using the derived secret key
		byte[] ciphertext = doCrypto(Cipher.ENCRYPT_MODE, MASK_ALG_FULL,
				maskKey, tokenPinIv, plaintext, fipsProvider);

		// wipe the intermediate results from memory
		Password.wipeBytes(plaintext);
		tokenPin.clear();

		return ciphertext;
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
	public static Password unmaskTokenPin(byte[] maskedTokenPin,
			SecretKey maskKey, byte[] tokenPinIv, Provider provider)
			throws Exception {
		// decrypt the token pin using the derived secret key
		byte[] plaintext = doCrypto(Cipher.DECRYPT_MODE, MASK_ALG_FULL,
				maskKey, tokenPinIv, maskedTokenPin, provider);

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
	 * Reads sensitive strings securely without using immutable strings.
	 * 
	 * @return the sensitive string. Please clear the returned value after use.
	 */
	public static Password readSensitiveString(String prompt) {
		Password first = null;
		Password second = null;

		try {
			do {
				if (first != null) {
					System.out.println("\nThe values do not match.  "
							+ "Please try again.");
				}

				System.out.print("\nPlease enter the " + prompt + ": ");
				first = Password.readPasswordFromConsole();

				System.out.print("Please confirm the " + prompt + ": ");
				second = Password.readPasswordFromConsole();
			} while (!first.equals(second));
		} catch (GiveUpException e) {
			System.err.println("No " + prompt + " supplied");

			if (first != null)
				first.clear();
		}

		if (second != null)
			second.clear();

		return first;
	}

	/**
	 * Wrap the secret key given the public key and provider.
	 * 
	 * @param pub
	 *            the public key
	 * @param provider
	 *            the provider to wrap the key
	 * @param secret
	 *            the key to be wrapped
	 * @return the wrapped secret key
	 */
	private static byte[] doWrapKey(PublicKey pub, Provider provider,
			SecretKey secret) {
		byte[] wrappedKey = new byte[0];

		try {
			// wrap the admin key using the cert priv key
			Cipher cipher = Cipher.getInstance(ADMIN_KEY_WRAP_ALG, provider);
			cipher.init(Cipher.WRAP_MODE, pub);
			wrappedKey = cipher.wrap(secret);
		} catch (Exception e) {
			LOGGER.error("failed to wrap the key", e);
		}

		return wrappedKey;
	}

	/**
	 * Unwrap the wrapped key given the private key and provider.
	 * 
	 * @param priv
	 *            the private key
	 * @param the
	 *            provider to unwrap the key
	 * @param wrappedKey
	 *            the wrapped secret key
	 * @return the unwrapped secret key
	 */
	private static SecretKey doUnwrapKey(PrivateKey priv, Provider provider,
			byte[] wrappedKey) throws Exception {
		SecretKey unwrappedKey = null;

		if (wrappedKey != null) {
			// unwrap the admin key using the cert priv key
			Cipher cipher = Cipher.getInstance(ADMIN_KEY_WRAP_ALG, provider);
			cipher.init(Cipher.UNWRAP_MODE, priv);
			unwrappedKey = (SecretKey) cipher.unwrap(wrappedKey,
					ADMIN_KEY_TYPE, Cipher.SECRET_KEY);
		}

		return unwrappedKey;
	}

	/**
	 * Find the vault certificate
	 * 
	 * @param store
	 * @return
	 * @throws TokenException
	 */
	private static X509Certificate findVaultCert(CryptoStore store)
			throws TokenException {
		int i = 0;

		for (X509Certificate cert : store.getCertificates()) {
			if (cert.getNickname().trim().equals(VAULTCERT_NICKNAME))
				return cert;
		}

		throw new TokenException("Certificate with nickname '"
				+ VAULTCERT_NICKNAME + "' is missing");
	}

	/**
	 * Find the matching private key for the vault cert. There is no easy way to
	 * do this other than wrap a test key and then successively try to unwrap it
	 * until successful.
	 * 
	 * @param store
	 *            the crypto store containing the vault cert
	 * @param provider
	 *            the fips provider
	 * @return index of the private key for the vault
	 */
	private static int findVaultPrivKeyIndex(CryptoStore store,
			Provider provider) throws TokenException {
                X509Certificate cert = findVaultCert(store);
                PublicKey pub = cert.getPublicKey();

		SecretKey testKey = null;
		try {
			testKey = generateAdminKey();
		} catch (Exception ignored) {
		}

		byte[] wrappedTest = doWrapKey(pub, provider, testKey);

		int i = 0;
		for (PrivateKey priv : store.getPrivateKeys()) {
			SecretKey unwrappedTest = null;
			try {
				unwrappedTest = doUnwrapKey(priv, provider, wrappedTest);
			} catch (Exception ignored) {
			}

			if (unwrappedTest != null)
				return i;
			++i;
		}
		
		throw new TokenException("Cannot match private key for vault cert");
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
