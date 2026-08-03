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
package org.springframework.security.access.vote;

import java.util.List;

import org.junit.Test;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2024-22257 (backpatch of the upstream 5.7.12/5.8.11 fix,
 * gh-14715).
 *
 * <p>{@code AuthenticatedVoter.isFullyAuthenticated} delegated straight to
 * {@code AuthenticationTrustResolver}, whose {@code isAnonymous}/{@code isRememberMe}
 * both return {@code false} for a {@code null} {@code Authentication}. A null
 * authentication therefore read as "fully authenticated" and the voter returned
 * ACCESS_GRANTED for an unauthenticated caller.
 *
 * <p>All three attribute levels are affected and all three tests fail on the unpatched
 * 4.2.20.RELEASE: every branch of {@code vote} reaches {@code isFullyAuthenticated}.
 */
public class AuthenticatedVoterNullAuthenticationTests {

	@Test
	public void voteWhenAuthenticationNullAndFullyRequiredThenDenied() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		List<ConfigAttribute> attributes = SecurityConfig
				.createList(AuthenticatedVoter.IS_AUTHENTICATED_FULLY);

		assertThat(voter.vote(null, null, attributes))
				.isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void voteWhenAuthenticationNullAndRememberedRequiredThenDenied() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		List<ConfigAttribute> attributes = SecurityConfig
				.createList(AuthenticatedVoter.IS_AUTHENTICATED_REMEMBERED);

		assertThat(voter.vote(null, null, attributes))
				.isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void voteWhenAuthenticationNullAndAnonymousRequiredThenDenied() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		List<ConfigAttribute> attributes = SecurityConfig
				.createList(AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY);

		assertThat(voter.vote(null, null, attributes))
				.isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}
}
