package com.github.torleifg.maskinporten;

record JwtGrantResponse(String accessToken, String tokenType, int expiresIn, String scope) {}
