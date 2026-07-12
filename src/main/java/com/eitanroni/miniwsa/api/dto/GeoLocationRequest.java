package com.eitanroni.miniwsa.api.dto;

import jakarta.validation.constraints.NotBlank;

public record GeoLocationRequest(

        @NotBlank
        String country,

        String city
) {
}