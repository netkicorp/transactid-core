package com.netki.keygeneration.repo.data

import com.google.gson.annotations.SerializedName

internal data class AttestationsRequest(
    @SerializedName("attestations")
    val attestations: List<AttestationField>
)
