/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
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
package org.jboss.security.fips;

import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;

@MessageLogger(projectCode = "FIPS")
public interface FIPSLogger extends BasicLogger {

	FIPSLogger LOGGER = Logger.getMessageLogger(FIPSLogger.class, FIPSLogger.class.getPackage().getName());

	@LogMessage(level = Logger.Level.TRACE)
	@Message(id = 355, value = "Begin execPasswordCmd, command: %s")
	void traceBeginExecPasswordCmd(String passwordCmd);

	@LogMessage(level = Logger.Level.TRACE)
	@Message(id = 356, value = "End execPasswordCmd, exit code: %s")
	void traceEndExecPasswordCmd(int exitCode);

	@LogMessage(level = Logger.Level.INFO)
	@Message(id = 361, value = "FIPS Security Vault Implementation Initialized and Ready")
	void infoVaultInitialized();

	@LogMessage(level = Logger.Level.TRACE)
	@Message(id = 363, value = "Retrieving password from the cache for key: %s")
	void traceRetrievingPasswordFromCache(String newKey);

	@LogMessage(level = Logger.Level.TRACE)
	@Message(id = 364, value = "Storing password to the cache for key: %s")
	void traceStoringPasswordToCache(String newKey);

	@LogMessage(level = Logger.Level.TRACE)
	@Message(id = 365, value = "Resetting cache")
	void traceResettingCache();

	@LogMessage(level = Logger.Level.ERROR)
	@Message(id = 366, value = "Error parsing time out number.")
	void errorParsingTimeoutNumber();

	@LogMessage(level = Logger.Level.INFO)
	@Message(id = 371, value = "Security Vault keystore does not contain SecretKey entry under alias (%s)")
	void vaultDoesNotContainSecretKey(String alias);

	@LogMessage(level = Logger.Level.TRACE)
	@Message(id = 372, value = "decoded vault data directory: %s")
	void traceDecodedVaultDirectory(String vaultDir);

	@LogMessage(level = Logger.Level.INFO)
	@Message(id = 373, value = "Generating a new admin key under alias (%s)")
	void generatingNewAdminKey(String alias);
}
