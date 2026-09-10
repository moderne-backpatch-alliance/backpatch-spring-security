/*
 * Copyright 2002-2026 the original author or authors.
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

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests that {@link X509AuthenticationFilter}'s DEFAULT principal extractor is the one
 * that reads the subject through {@link javax.security.auth.x500.X500Principal}.
 *
 * These go through the filter rather than through an extractor directly on purpose:
 * CVE-2026-47838 is fixed by changing which extractor a consumer gets when they configure
 * none, so the default is the thing under test. An assertion against
 * {@link SubjectX500PrincipalExtractor} alone would pass on a baseline whose filter still
 * defaults to {@link SubjectDnX509PrincipalExtractor}.
 */
public class X509AuthenticationFilterTests {

	private final X509AuthenticationFilter filter = new X509AuthenticationFilter();

	// CVE-2026-47838: the certificate's real CN is "luke"; its OU value is the literal
	// string "CN=duke,". getSubjectDN().getName() renders that OU unescaped and
	// least-specific first, so a regex looking for the first "CN=" reads "duke".
	@Test
	public void getPreAuthenticatedPrincipalWhenCnEmbeddedInAnotherRdnThenUsesRealCn() throws Exception {
		Object principal = this.filter.getPreAuthenticatedPrincipal(request(X509TestUtils.buildTestCertficateWithEmbeddedDn()));
		assertThat(principal).isEqualTo("luke");
	}

	@Test
	public void getPreAuthenticatedPrincipalWhenOrdinaryCertificateThenUnchanged() throws Exception {
		Object principal = this.filter.getPreAuthenticatedPrincipal(request(X509TestUtils.buildTestCertificate()));
		assertThat(principal).isEqualTo("Luke Taylor");
	}

	@Test
	public void getPreAuthenticatedPrincipalWhenNoCertificateThenNull() {
		assertThat(this.filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest())).isNull();
	}

	private static MockHttpServletRequest request(X509Certificate certificate) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("javax.servlet.request.X509Certificate", new X509Certificate[] { certificate });
		return request;
	}

}
