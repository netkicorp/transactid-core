package com.netki.util

import io.ktor.http.*

val Url.hostWithPortIfRequired: String get() = if (port == protocol.defaultPort) host else hostWithPort

val Url.fullUrl: String get() = "${protocol.name}://$hostWithPortIfRequired$fullPath"
