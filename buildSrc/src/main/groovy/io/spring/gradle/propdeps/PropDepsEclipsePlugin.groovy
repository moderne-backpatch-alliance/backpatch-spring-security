package io.spring.gradle.propdeps

import org.gradle.api.Plugin
import org.gradle.api.Project

/** IDE/pom metadata half of propdeps; nothing in a backpatch build consumes it. */
class PropDepsEclipsePlugin implements Plugin<Project> {
	@Override
	void apply(Project project) {
	}
}
