plugins {
    java
    kotlin("jvm") version "1.4.30"
}

val groupId = "com.netki"
val artifactId = "transactid-core"
val versionRelease = "2.0.0-beta1"

group = groupId
version = versionRelease

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib"))
    testCompile("junit", "junit", "4.12")
}
