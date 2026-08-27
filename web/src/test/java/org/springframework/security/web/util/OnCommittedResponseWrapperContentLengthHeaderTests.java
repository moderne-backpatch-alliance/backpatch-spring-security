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

package org.springframework.security.web.util;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

/**
 * Regression tests for CVE-2026-22732: {@link OnCommittedResponseWrapper} must track a
 * {@code Content-Length} response header set through {@code setHeader}, {@code setIntHeader},
 * or {@code addIntHeader}, not only through {@code addHeader}. When the length is untracked,
 * {@link OnCommittedResponseWrapper#onResponseCommitted()} never fires as the body is written,
 * so security headers applied at commit time are silently dropped.
 *
 * <p>Backpatch-fresh: not present upstream in the 5.7.x line. Mirrors the tracking added in
 * spring-projects/spring-security@c3e1a94d8ca4455f30240ec0e56809bf3c48e67b (PR gh-19087).
 *
 * @see OnCommittedResponseWrapper
 */
@ExtendWith(MockitoExtension.class)
public class OnCommittedResponseWrapperContentLengthHeaderTests {

	@Mock
	HttpServletResponse delegate;

	@Mock
	PrintWriter writer;

	OnCommittedResponseWrapper response;

	boolean committed;

	@BeforeEach
	public void setup() {
		this.response = new OnCommittedResponseWrapper(this.delegate) {
			@Override
			protected void onResponseCommitted() {
				OnCommittedResponseWrapperContentLengthHeaderTests.this.committed = true;
			}
		};
	}

	// Content-Length set via setIntHeader must be tracked, so writing that many
	// bytes commits the response. Without the fix setIntHeader is not overridden
	// and the length is never recorded, so the response never commits.
	@Test
	public void setIntHeaderContentLengthTriggersOnResponseCommitted() throws IOException {
		given(this.delegate.getWriter()).willReturn(this.writer);
		int expected = 1234;
		this.response.setIntHeader("Content-Length", String.valueOf(expected).length());
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void addIntHeaderContentLengthTriggersOnResponseCommitted() throws IOException {
		given(this.delegate.getWriter()).willReturn(this.writer);
		int expected = 1234;
		this.response.addIntHeader("Content-Length", String.valueOf(expected).length());
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

	// setHeader(String, String) is the third path the fix newly tracks (addHeader
	// was already tracked). Header name matching is case-insensitive.
	@Test
	public void setHeaderContentLengthTriggersOnResponseCommitted() throws IOException {
		given(this.delegate.getWriter()).willReturn(this.writer);
		int expected = 1234;
		this.response.setHeader("content-length", String.valueOf(String.valueOf(expected).length()));
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

}
