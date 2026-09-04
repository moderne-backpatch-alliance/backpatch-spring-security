package io.spring.gradle.springio

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Stub for io.spring.gradle:spring-io-plugin:0.0.8.RELEASE, 404 on Central and on the Gradle
 * Plugin Portal and served only by repo.spring.io, which answers 401.
 *
 * SpringIoConventionPlugin imports this type unconditionally, and io.spring.convention.spring-module
 * applies that convention, so the type has to exist for buildSrc to compile. The convention
 * applies THIS plugin only under `project.hasProperty('platformVersion')`, which selects the
 * Spring IO Platform dependency-matrix test run; this build never sets it.
 *
 * It throws rather than doing nothing, because "never applied" is a property of the build and
 * not of this class. If some later run does set platformVersion, that fails loudly at
 * configuration time instead of silently dropping the springIoTestRuntime wiring it asked for.
 */
class SpringIoPlugin implements Plugin<Project> {
	@Override
	void apply(Project project) {
		throw new UnsupportedOperationException(
			"spring-io-plugin is unavailable to this backpatch build (404 on Central and the "
			+ "Gradle Plugin Portal, 401 on repo.spring.io); it is reached only via "
			+ "platformVersion, which this build does not set")
	}
}
