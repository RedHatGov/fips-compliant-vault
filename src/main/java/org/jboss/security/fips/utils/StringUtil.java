/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.security.fips.FIPSVaultMessages;

/**
 * Utility dealing with Strings
 * 
 * @author Anil.Saldhana@redhat.com
 * @author Rich Lucente (rlucente_at_redhat_dot_com)
 * @since Oct 21, 2009
 */
public class StringUtil {
	public static final String PROPERTY_DEFAULT_SEPARATOR = "::";

	/**
	 * Check whether the passed string is null or empty
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isNotNull(String str) {
		return str != null && !"".equals(str.trim());
	}

	/**
	 * Check whether the string is null or empty
	 * 
	 * @param str
	 * @return
	 */
	public static boolean isNullOrEmpty(String str) {
		return str == null || str.isEmpty();
	}

	/**
	 * <p>
	 * Get the system property value if the string is of the format
	 * ${sysproperty}
	 * </p>
	 * <p>
	 * You can insert default value when the system property is not set, by
	 * separating it at the beginning with ::
	 * </p>
	 * <p>
	 * <b>Examples:</b>
	 * </p>
	 * 
	 * <p>
	 * ${idp} should resolve to a value if the system property "idp" is set.
	 * </p>
	 * <p>
	 * ${idp::http://localhost:8080} will resolve to http://localhost:8080 if
	 * the system property "idp" is not set.
	 * </p>
	 * 
	 * @param str
	 * @return
	 */
	public static String getSystemPropertyAsString(String str) {
		if (str == null)
			throw FIPSVaultMessages.MESSAGES.invalidNullArgument("str");
		if (str.contains("${")) {
			Pattern pattern = Pattern.compile("\\$\\{([^}]+)}");
			Matcher matcher = pattern.matcher(str);

			StringBuffer buffer = new StringBuffer();
			String sysPropertyValue = null;

			while (matcher.find()) {
				String subString = matcher.group(1);
				String defaultValue = "";

				// Look for default value
				if (subString.contains(StringUtil.PROPERTY_DEFAULT_SEPARATOR)) {
					int index = subString.indexOf(StringUtil.PROPERTY_DEFAULT_SEPARATOR);
					defaultValue = subString.substring(index + StringUtil.PROPERTY_DEFAULT_SEPARATOR.length());
					subString = subString.substring(0, index);
				}
				sysPropertyValue = SecurityActions.getSystemProperty(subString, defaultValue);
				if (sysPropertyValue.isEmpty()) {
					throw FIPSVaultMessages.MESSAGES.missingSystemProperty(matcher.group(1));
				}
				// in case of backslash on Win replace with double backslash
				matcher.appendReplacement(buffer, sysPropertyValue.replace("\\", "\\\\"));
			}

			matcher.appendTail(buffer);
			str = buffer.toString();
		}
		return str;
	}

	/**
	 * Match two strings else throw a {@link RuntimeException}
	 * 
	 * @param first
	 * @param second
	 */
	public static void match(String first, String second) {
		if (first.equals(second) == false)
			throw FIPSVaultMessages.MESSAGES.failedToMatchStrings(first, second);
	}

	/**
	 * Given a comma separated string, get the tokens as a {@link List}
	 * 
	 * @param str
	 * @return
	 */
	public static List<String> tokenize(String str) {
		List<String> list = new ArrayList<String>();
		StringTokenizer tokenizer = new StringTokenizer(str, ",");
		while (tokenizer.hasMoreTokens()) {
			list.add(tokenizer.nextToken());
		}
		return list;
	}
}