package io.spring.gradle.propdeps

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlugin

/**
 * Stands in for io.spring.gradle:propdeps-plugin, which was only ever published to
 * repo.spring.io (anonymous access now returns 401) and exists on no other public
 * repository at any version. Registers the same two configurations the module build
 * files declare dependencies in, and puts them on the same classpaths the original
 * did. Publication scopes are NOT reproduced here and do not need to be: this
 * candidate ships via repackage_from_original, so the deployed pom is Central's own.
 */
class PropDepsPlugin implements Plugin<Project> {
	@Override
	void apply(Project project) {
		project.pluginManager.apply(JavaPlugin)
		def provided = project.configurations.maybeCreate('provided')
		def optional = project.configurations.maybeCreate('optional')
		project.sourceSets.main.compileClasspath += provided + optional
		project.sourceSets.test.compileClasspath += provided + optional
		project.sourceSets.test.runtimeClasspath += provided + optional
		project.tasks.withType(org.gradle.api.tasks.javadoc.Javadoc) { t ->
			t.classpath += provided + optional
		}
	}
}
