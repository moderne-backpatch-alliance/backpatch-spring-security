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

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2022-22978 (backpatch of the upstream 5.4.11/5.5.7/5.6.4
 * fix, gh-11234).
 *
 * <p>{@code RegexRequestMatcher} compiled its pattern with no flags, so {@code .} did
 * not match a line terminator. A path carrying an encoded newline therefore failed to
 * match an otherwise-covering authorization rule, and the request slipped past the
 * constraint entirely. Compiling with {@link java.util.regex.Pattern#DOTALL} makes the
 * rule match the request it is meant to guard.
 *
 * <p>Each test asserts {@code matches(...) == true}: matching is what causes the
 * security rule to be APPLIED. All fail on the unpatched 4.2.20.RELEASE.
 */
public class RegexRequestMatcherNewlineBypassTests {

	@Test
	public void matchesWhenServletPathContainsLineFeedThenRuleStillApplies() {
		RegexRequestMatcher matcher = new RegexRequestMatcher(".*", null);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah%0a");
		request.setServletPath("/blah\n");

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesWhenServletPathContainsCarriageReturnThenRuleStillApplies() {
		RegexRequestMatcher matcher = new RegexRequestMatcher(".*", null);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah%0d");
		request.setServletPath("/blah\r");

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesWhenCaseInsensitiveAndPathContainsLineFeedThenRuleStillApplies() {
		RegexRequestMatcher matcher = new RegexRequestMatcher("/BLAH.*", null, true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah%0a");
		request.setServletPath("/blah\n");

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesWhenCaseInsensitiveThenStillCaseInsensitive() {
		RegexRequestMatcher matcher = new RegexRequestMatcher("/BLAH", null, true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah");
		request.setServletPath("/blah");

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesWhenCaseSensitiveThenStillCaseSensitive() {
		RegexRequestMatcher matcher = new RegexRequestMatcher("/BLAH", null);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah");
		request.setServletPath("/blah");

		assertThat(matcher.matches(request)).isFalse();
	}
}
