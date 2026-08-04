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
package org.springframework.security.web.util.matcher;

import java.util.Locale;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2024-38827 (backpatch of the upstream 5.7.14/5.8.16/6.x fix,
 * commit 0eaffb37e7 "Require Locale argument for toLower/toUpperCase usage").
 *
 * <p>Case-insensitive {@code AntPathRequestMatcher} folded both the configured pattern
 * and the incoming path with the no-argument {@code String.toLowerCase()}, which uses the
 * JVM default locale. In a Turkish locale {@code "I"} lowercases to the dotless
 * {@code "ı"} rather than {@code "i"}, so a pattern written with an uppercase I folded
 * to something the request path could never start with. The authorization rule then failed
 * to match the request it was written to guard, and the request slipped past the
 * constraint — the same bypass shape as CVE-2022-22978, reached by a different route.
 *
 * <p>Each test asserts {@code matches(...) == true}: matching is what causes the security
 * rule to be APPLIED. Both fail on the unpatched 4.2.20.RELEASE when the default locale is
 * Turkish, and the default locale is a deployment property an application does not
 * normally think of as security-relevant.
 */
public class AntPathRequestMatcherLocaleBypassTests {

	private static final Locale TURKISH = new Locale("tr", "TR");

	private Locale original;

	@Before
	public void setUp() {
		this.original = Locale.getDefault();
		Locale.setDefault(TURKISH);
	}

	@After
	public void tearDown() {
		Locale.setDefault(this.original);
	}

	/**
	 * Guards the {@code SubpathMatcher} path, taken for a pattern ending in {@code /**}.
	 */
	@Test
	public void matchesWhenSubpathPatternHasUppercaseIAndTurkishDefaultLocaleThenRuleStillApplies() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/ADMIN/**", null, false);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/users");
		request.setServletPath("/admin/users");

		assertThat(matcher.matches(request)).isTrue();
	}

	/**
	 * The same fold is applied to the request path, so an uppercase I arriving on the
	 * request must still land inside a lowercase rule.
	 */
	@Test
	public void matchesWhenRequestPathHasUppercaseIAndTurkishDefaultLocaleThenRuleStillApplies() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/admin/**", null, false);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ADMIN/users");
		request.setServletPath("/ADMIN/users");

		assertThat(matcher.matches(request)).isTrue();
	}
}
