package org.jboss.security.fips;

import org.jboss.logging.*;

@SuppressWarnings("deprecation")
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
