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
package org.springframework.security.web.context;

import org.junit.After;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2021-22112 (backpatch of the upstream 5.2.9/5.3.8/5.4.4 fix,
 * gh-9387).
 *
 * <p>When something in the chain committed the response (sendError/sendRedirect/
 * flushBuffer), {@code SaveToSessionResponseWrapper} wrote the then-current
 * SecurityContext to the session and flagged itself saved. The repository's own
 * {@code saveContext} then declined to run a second time, so a context that was
 * elevated mid-request and afterwards restored kept the ELEVATED context in the
 * session — privilege escalation persisted into subsequent requests.
 *
 * <p>The fix drops the once-per-request guard and instead tracks, on the wrapper,
 * whether a save already happened; if so a later save is always treated as a change.
 */
public class HttpSessionSecurityContextRepositoryReSaveTests {

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	/**
	 * Fails on the unpatched 4.2.20.RELEASE: the session keeps the elevated context.
	 */
	@Test
	public void saveContextWhenElevatedContextCommittedThenRestoredThenRestoredContextIsStored() {
		HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		repository.loadContext(holder);

		SecurityContext elevated = SecurityContextHolder.createEmptyContext();
		elevated.setAuthentication(new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN"));
		SecurityContextHolder.setContext(elevated);
		// commits the response, which makes the wrapper save the elevated context
		flush(holder);

		assertThat(storedContext(request)).isEqualTo(elevated);

		SecurityContext original = SecurityContextHolder.createEmptyContext();
		original.setAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		SecurityContextHolder.setContext(original);
		repository.saveContext(original, holder.getRequest(), holder.getResponse());

		assertThat(storedContext(request)).isEqualTo(original);
	}

	/**
	 * The un-elevated path must be unchanged: with no intervening commit, a single
	 * save still stores the context exactly once.
	 */
	@Test
	public void saveContextWhenResponseNotCommittedThenContextIsStored() {
		HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		repository.loadContext(holder);

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		repository.saveContext(context, holder.getRequest(), holder.getResponse());

		assertThat(storedContext(request)).isEqualTo(context);
	}

	private void flush(HttpRequestResponseHolder holder) {
		try {
			holder.getResponse().flushBuffer();
		}
		catch (java.io.IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private Object storedContext(MockHttpServletRequest request) {
		return request.getSession()
				.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
	}
}
