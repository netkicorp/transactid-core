package com.netki.extensions

import java.util.regex.Pattern

private const val REGEX = "^[a-zA-Z0-9_. -]+$"
private val PATTERN: Pattern = Pattern.compile(REGEX)

/**
 * Validate if an string contains only alphanumeric and white spaces characters
 */
internal fun String.isAlphaNumeric() = PATTERN.matcher(this).matches()
