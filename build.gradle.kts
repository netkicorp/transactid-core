import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    kotlin("jvm") version "1.4.30"
    `maven-publish`
    signing
    id("org.jetbrains.dokka") version "0.9.17" apply false
}

val groupId = "com.netki"
val artifactId = "transactid-core"
val versionRelease = "3.0.0-beta1"

val protoVersion = "3.10.0"
val ktorVersion = "1.3.2"
val jacksonVersion = "2.11.3"
val bouncyCastleVersion = "1.65"
val kotlinReflectVersion = "1.4.30"
val junitVersion = "5.3.1"
val mockitoVersion = "3.4.6"

group = groupId
version = versionRelease

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.kotlin:kotlin-reflect:$kotlinReflectVersion")

    implementation("com.google.protobuf:protobuf-java:$protoVersion")

    implementation("io.ktor:ktor-client-okhttp:$ktorVersion")
    implementation("io.ktor:ktor-client-json:$ktorVersion")
    implementation("io.ktor:ktor-client-gson:$ktorVersion")
    implementation("io.ktor:ktor-client-logging-jvm:$ktorVersion")

    implementation("com.fasterxml.jackson.core:jackson-annotations:$jacksonVersion")
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")

    implementation("org.bouncycastle:bcprov-jdk15on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk15on:$bouncyCastleVersion")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")

    testImplementation("org.mockito:mockito-core:$mockitoVersion")

    testImplementation("io.ktor:ktor-client-mock:$ktorVersion")
    testImplementation("io.ktor:ktor-client-mock-jvm:$ktorVersion")
    testImplementation("io.ktor:ktor-client-mock-js:$ktorVersion")
    testImplementation("io.ktor:ktor-client-mock-native:$ktorVersion")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.named<KotlinCompile>("compileKotlin") {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.named<KotlinCompile>("compileTestKotlin") {
    kotlinOptions.jvmTarget = "1.8"
}

val dokka = tasks.withType<DokkaTask> {
    outputFormat = "html"
    outputDirectory = "$buildDir/javadoc"
}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets["main"].allSource)
}

val javadocJar by tasks.registering(Jar::class) {
    dependsOn(dokka)
    archiveClassifier.set("javadoc")
    from(buildDir.resolve("javadoc"))
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = groupId
            artifactId = artifactId
            version = versionRelease

            from(components["java"])
            artifact(sourcesJar)
            artifact(javadocJar)

            pom {
                description.set("Core components for TransactId")
                name.set("Transactid-Core Java Library")
                url.set("https://github.com/netkicorp/transactid-core")

                withXml {
                    asNode().appendNode("packaging", "jar")
                }

                organization {
                    name.set("com.netki")
                    url.set("https://netki.com")
                }
                issueManagement {
                    system.set("GitHub")
                    url.set("https://github.com/netkicorp/transactid-core/issues")
                }

                licenses {
                    license {
                        name.set("BSD 3-Clause")
                        url.set("https://github.com/netkicorp/transactid-core/blob/master/LICENSE")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        name.set("Netki Development")
                    }
                }
                scm {
                    url.set("https://github.com/netkicorp/transactid-core")
                    connection.set("scm:git:git://github.com/netkicorp/transactid-core.git")
                    developerConnection.set("scm:git:ssh://git@github.com:/netkicorp/transactid-core.git")
                }

            }
        }
    }

    repositories {
        maven {
            url = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = project.property("sonatypeUsername") as String
                password = project.property("sonatypePassword") as String
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

tasks {
    test {
        useJUnitPlatform()
        testLogging {
            events("skipped", "passed", "failed")
            showStandardStreams = false
            showExceptions = false
            addTestListener(object : TestListener {
                override fun beforeSuite(suite: TestDescriptor) {}
                override fun beforeTest(testDescriptor: TestDescriptor) {}
                override fun afterTest(testDescriptor: TestDescriptor, result: TestResult) {}
                override fun afterSuite(suite: TestDescriptor, result: TestResult) {
                    if (suite.parent != null) {
                        val output =
                            "Results: ${result.resultType} (${result.testCount} tests, ${result.successfulTestCount} passed, ${result.failedTestCount} failed, ${result.skippedTestCount} skipped)"
                        val startItem = "|  "
                        val endItem = "  |"
                        val repeatLength = startItem.length + output.length + endItem.length
                        println("\n${"-".repeat(repeatLength)}\n$startItem$output$endItem\n${"-".repeat(repeatLength)}")
                    }
                }
            })
        }
    }
}
