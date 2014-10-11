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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.jboss.logging.Logger;
import org.jboss.security.Base64Utils;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.util.Password;

/**
 * Utility functions for FIPS compliant vault cryptography.
 * 
 * @author Rich Lucente
 * @since Oct 10, 2014
 */
public class FIPSCryptoUtil {

	private static final Logger LOGGER = Logger.getLogger(FIPSCryptoUtil.class);

	private static final String ADMIN_KEY_TYPE = "AES";
	private static final String ADMIN_KEY_WRAP_ALG = "RSA";

	// token pin mask parameters
	private static final String MASK_ALG_CRYPTO = "DESede";
	private static final String MASK_ALG_FULL = MASK_ALG_CRYPTO
			+ "/CBC/PKCS5Padding";

	// vault-option names and parsing constants
	private static final String MASKED_TOKEN_PREFIX = "MASK-";

	// NIST Special Publication 800-132 recommendations for PBKDF2 algorithm
	private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA1";
	private static final int PBE_MIN_ITERATION_COUNT = 1000;

	// fixed string to seed PBE, see http://xkcd.com/221/
	private static final String PBE_SEED = "areallylongthrowawaystringthatdoesnotmatter";

	// provider names
	private static final String FIPS_PROVIDER_NAME = "Mozilla-JSS";
	private static final String NONFIPS_PROVIDER_NAME = "SunJCE";

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

	/**
	 * Encrypt/decrypt given data.
	 * 
	 * @param mode
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
				salt, PBE_MIN_ITERATION_COUNT,
				DESedeKeySpec.DES_EDE_KEY_LEN * 8);
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
				// get the private key to unwrap the admin key
				CryptoStore store = fipsToken.getCryptoStore();
				PublicKey pub = store.getCertificates()[0].getPublicKey();

				// unwrap the admin key using the cert priv key
				Cipher cipher = Cipher.getInstance(ADMIN_KEY_WRAP_ALG,
						fipsProvider);
				cipher.init(Cipher.WRAP_MODE, pub);
				wrappedKey = cipher.wrap(adminKey);
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
				PrivateKey priv = store.getPrivateKeys()[0];

				// unwrap the admin key using the cert priv key
				Cipher cipher = Cipher.getInstance(ADMIN_KEY_WRAP_ALG,
						fipsProvider);
				cipher.init(Cipher.UNWRAP_MODE, priv);
				unwrappedKey = (SecretKey) cipher.unwrap(wrappedKey,
						ADMIN_KEY_TYPE, Cipher.SECRET_KEY);
			} catch (Exception e) {
				LOGGER.error("failed to unwrap the key", e);
			}
		}

		return unwrappedKey;
	}

	/**
	 * Mask the NSS token password using the Mozilla JSS provider.
	 */
	public static String maskTokenPin(Password tokenPin, SecretKey maskKey,
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

		return MASKED_TOKEN_PREFIX + Base64Utils.tob64(ciphertext);
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
	public static Password unmaskTokenPin(String maskedTokenPin,
			SecretKey maskKey, byte[] tokenPinIv, Provider provider)
			throws Exception {
		// get the encrypted token pin
		maskedTokenPin = maskedTokenPin.substring(MASKED_TOKEN_PREFIX.length());
		byte[] ciphertext = Base64Utils.fromb64(maskedTokenPin);

		// decrypt the token pin using the derived secret key
		byte[] plaintext = doCrypto(Cipher.DECRYPT_MODE, MASK_ALG_FULL,
				maskKey, tokenPinIv, ciphertext, provider);

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
