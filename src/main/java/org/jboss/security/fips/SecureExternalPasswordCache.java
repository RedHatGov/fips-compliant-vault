/*
* JBoss, Home of Professional Open Source
* Copyright 2005, JBoss Inc., and individual contributors as indicated
* by the @authors tag. See the copyright.txt in the distribution for a
* full listing of individual contributors.
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

package org.jboss.security.fips;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.jboss.security.fips.utils.CryptoUtil;

/**
 * External command password cache where all passwords are stored encrypted.
 * Singleton password cache.
 * 
 * @author Peter Skopek <pskopek@redhat.com>
 * @author Rich Lucente <rlucente_at_redhat_dot_com>
 * @version $Revision:$
 */
public class SecureExternalPasswordCache implements PasswordCache {

	private static final SecureExternalPasswordCache PASSWORD_CACHE = new SecureExternalPasswordCache();

	private SecretKey key;
	private Map<String, PasswordRecord> cache;

	/**
	 * Create a thread-safe cache and a cryptographic key for encrypting
	 * passwords. Each password will have it's own iv for encryption. This will
	 * throw a runtime exception if the FIPS provider is not available.
	 */
	private SecureExternalPasswordCache() {
		cache = Collections.synchronizedMap(new HashMap<String, PasswordRecord>());
		try {
			key = CryptoUtil.generateKey();
		} catch (Throwable t) {
			throw FIPSVaultMessages.MESSAGES.unableToInitializePasswordCache(t);
		}
	}

	/**
	 * Get the singleton instance of this class. If a security manager is in
	 * place, this method must be granted RuntimePermission.
	 * 
	 * @return singleton instance of this class
	 */
	public static SecureExternalPasswordCache getExternalPasswordCacheInstance() {
		SecurityManager sm = System.getSecurityManager();
		if (sm != null) {
			sm.checkPermission(new RuntimePermission(
					SecureExternalPasswordCache.class.getName() + ".getExternalPasswordCacheInstance"));
		}
		return PASSWORD_CACHE;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jboss.security.PasswordCache#contains(java.lang.String)
	 */
	@Override
	public boolean contains(String key, long timeOut) {
		String transformedKey = transformKey(key);
		PasswordRecord pr = cache.get(transformedKey);
		if (pr != null && (timeOut == 0 || System.currentTimeMillis() - pr.insertionTime < timeOut)) {
			return true;
		}
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jboss.security.PasswordCache#getPassword(java.lang.String)
	 */
	@Override
	public char[] getPassword(String key) {
		String newKey = transformKey(key);
		PasswordRecord pr = cache.get(newKey);
		char[] password = null;
		try {
			password = CryptoUtil.decryptB64(this.key, pr.iv, pr.b64EncryptedPassword);
		} catch (GeneralSecurityException e) {
			throw FIPSVaultMessages.MESSAGES.unableToRetrieveCachedPassword(e, key);
		}
		return password;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jboss.security.PasswordCache#storePassword(java.lang.String,
	 * char[])
	 */
	@Override
	public void storePassword(String key, char[] password) {
		String newKey = transformKey(key);
		FIPSLogger.LOGGER.traceStoringPasswordToCache(newKey);
		PasswordRecord pr = new PasswordRecord();
		pr.insertionTime = System.currentTimeMillis();
		try {
			pr.iv = CryptoUtil.genRandomBytes(CryptoUtil.KEY_STRENGTH);
			pr.b64EncryptedPassword = CryptoUtil.encryptB64(this.key, pr.iv, password);
		} catch (GeneralSecurityException e) {
			throw FIPSVaultMessages.MESSAGES.unableToStorePasswordInCache(e, key);
		}
		cache.put(newKey, pr);
	}

	/**
	 * @return number of cached passwords. Mainly for testing purpose.
	 */
	public int getCachedPasswordsCount() {
		return cache.size();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jboss.security.PasswordCache#reset()
	 */
	@Override
	public void reset() {
		FIPSLogger.LOGGER.traceResettingCache();
		cache.clear();
	}

	/**
	 * Use the secure digest to hash the given key which can be an arbitrary
	 * string.
	 * 
	 * @param key
	 *            arbitrary string to hash to good key for caching
	 * @return base-64 encoded hashed key
	 */
	private String transformKey(String key) {
		try {
			return CryptoUtil.digest(key);
		} catch (Throwable t) {
			throw FIPSVaultMessages.MESSAGES.unableToDigestPasswordKey(t);
		}
	}
}

/**
 * Simple holder class for password data.
 */
class PasswordRecord {
	// the time the password was added to the cache
	long insertionTime;

	// the initialization vector used to decrypt/encrypt the password
	byte[] iv;

	// the encrypted password encoded as a base-64 string
	String b64EncryptedPassword;
}