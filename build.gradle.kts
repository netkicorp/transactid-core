plugins {
    java
    kotlin("jvm") version "1.4.30"
}

val groupId = "com.netki"
val artifactId = "transactid-core"
val versionRelease = "2.0.0-beta1"

val protoVersion = "3.10.0"
val ktorVersion = "1.3.2"
val jacksonVersion = "2.11.3"
val bouncyCastleVersion = "1.67"
val kotlinReflectVersion = "1.4.30"

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

    testCompile("junit", "junit", "4.12")
}
