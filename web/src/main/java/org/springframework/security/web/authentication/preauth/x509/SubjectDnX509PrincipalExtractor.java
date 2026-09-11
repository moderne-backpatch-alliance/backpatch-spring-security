/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

/**
 * Obtains the principal from a certificate by matching a regular expression against the
 * attributes of the Subject, as returned by
 * {@link X509Certificate#getSubjectX500Principal()}.
 * <p>
 * The regular expression should contain a single group; for example the default
 * expression "CN=(.*?)(?:,|$)" matches the common name field. So "CN=Jimi Hendrix,
 * OU=..." will give a user name of "Jimi Hendrix".
 * <p>
 * The matches are case insensitive. So "emailAddress=(.*?)," will match
 * "EMAILADDRESS=jimi@hendrix.org, CN=..." giving a user name "jimi@hendrix.org"
 * <p>
 * The expression is applied to ONE ATTRIBUTE AT A TIME, most-specific first, and has to
 * match from the start of that attribute. It used to be applied to the whole subject DN
 * as rendered by the deprecated {@link X509Certificate#getSubjectDN()}, which QUOTES an
 * attribute value containing a comma rather than escaping it. A subject such as
 * {@code CN=luke, OU="CN=duke,", O=Example Corp} therefore carried a literal {@code CN=}
 * inside the OU value, the expression above matched that one instead of the real common
 * name, and anybody able to obtain a certificate with a chosen OU was extracted as some
 * other user (CVE-2026-47838). Matching an attribute at a time leaves an expression that
 * names {@code CN} unable to reach an attribute that is not a CN.
 * <p>
 * Because each attribute is matched on its own, the value the expression sees is the
 * decoded one -- neither quoted nor escaped -- so a value containing a comma is no longer
 * returned with the surrounding quote. An attribute type RFC 2253 does not name is
 * reported as a numeric OID, except for those the old rendering spelled out as a keyword,
 * which are preserved.
 *
 * @author Luke Taylor
 * @deprecated Please use {@link SubjectX500PrincipalExtractor} instead
 */
@Deprecated
public class SubjectDnX509PrincipalExtractor implements X509PrincipalExtractor, MessageSourceAware {

	/**
	 * The attribute types that the {@link X509Certificate#getSubjectDN()} rendering spelled
	 * out as a keyword but which RFC 2253 does not name. Passed to
	 * {@link X500Principal#getName(String, Map)} so that an expression naming one of them
	 * still matches, and so that its value is decoded rather than left DER-encoded.
	 * Measured against {@code sun.security.x509.X500Name}'s own output.
	 */
	private static final Map<String, String> LEGACY_KEYWORDS;

	static {
		Map<String, String> keywords = new HashMap<>();
		keywords.put("1.2.840.113549.1.9.1", "EMAILADDRESS");
		keywords.put("2.5.4.4", "SURNAME");
		keywords.put("2.5.4.5", "SERIALNUMBER");
		keywords.put("2.5.4.12", "T");
		keywords.put("2.5.4.42", "GIVENNAME");
		keywords.put("2.5.4.43", "INITIALS");
		keywords.put("2.5.4.44", "GENERATION");
		keywords.put("2.5.4.46", "DNQ");
		LEGACY_KEYWORDS = Collections.unmodifiableMap(keywords);
	}

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private Pattern subjectDnPattern;

	public SubjectDnX509PrincipalExtractor() {
		setSubjectDnRegex("CN=(.*?)(?:,|$)");
	}

	@Override
	public Object extractPrincipal(X509Certificate clientCert) {
		String subjectDN = clientCert.getSubjectX500Principal().getName(X500Principal.RFC2253, LEGACY_KEYWORDS);
		this.logger.debug(LogMessage.format("Subject DN is '%s'", subjectDN));
		String username = getSubject(subjectDN);
		this.logger.debug(LogMessage.format("Extracted Principal name is '%s'", username));
		return username;
	}

	private List<Rdn> getDns(String subjectDn) {
		try {
			// read most-specific first, see gh-19254
			List<Rdn> rdns = new ArrayList<>(new LdapName(subjectDn).getRdns());
			Collections.reverse(rdns);
			return rdns;
		}
		catch (InvalidNameException ex) {
			throw new BadCredentialsException("Failed to parse client certificate", ex);
		}
	}

	private String getSubject(String subjectDn) {
		for (Rdn rdn : getDns(subjectDn)) {
			String attribute = rdn.getType() + "=" + rdn.getValue();
			// Both forms, because an expression written against the old whole-DN rendering may
			// or may not require the separator that followed the attribute there:
			// "CN=(.*?)(?:,|$)" matches the bare attribute, "emailAddress=(.*?)," needs a comma.
			String username = match(attribute);
			if (username == null) {
				username = match(attribute + ",");
			}
			if (username != null) {
				return username;
			}
		}
		throw new BadCredentialsException(this.messages.getMessage("SubjectDnX509PrincipalExtractor.noMatching",
				new Object[] { subjectDn }, "No matching pattern was found in subject DN: {0}"));
	}

	private String match(String attribute) {
		Matcher matcher = this.subjectDnPattern.matcher(attribute);
		// lookingAt rather than find: the expression has to match from the START of the
		// attribute, which is what stops one naming CN being satisfied by another attribute.
		if (!matcher.lookingAt()) {
			return null;
		}
		Assert.isTrue(matcher.groupCount() == 1, "Regular expression must contain a single group ");
		return matcher.group(1);
	}

	/**
	 * Sets the regular expression which will by used to extract the user name from the
	 * certificate's Subject DN.
	 * <p>
	 * It should contain a single group; for example the default expression
	 * "CN=(.*?)(?:,|$)" matches the common name field. So "CN=Jimi Hendrix, OU=..." will
	 * give a user name of "Jimi Hendrix".
	 * <p>
	 * The matches are case insensitive. So "emailAddress=(.?)," will match
	 * "EMAILADDRESS=jimi@hendrix.org, CN=..." giving a user name "jimi@hendrix.org"
	 * <p>
	 * The expression is matched against one Subject attribute at a time and must match from
	 * the start of it, so it can only ever extract from the attribute type it names. See the
	 * class-level documentation.
	 * @param subjectDnRegex the regular expression to find in the subject
	 */
	public void setSubjectDnRegex(String subjectDnRegex) {
		Assert.hasText(subjectDnRegex, "Regular expression may not be null or empty");
		this.subjectDnPattern = Pattern.compile(subjectDnRegex, Pattern.CASE_INSENSITIVE);
	}

	/**
	 * @since 5.5
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}
