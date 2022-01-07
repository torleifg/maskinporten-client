package com.github.torleifg.maskinporten;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.io.IOException;
import java.time.Clock;
import java.util.Date;
import java.util.UUID;

public abstract class MaskinportenClient {
    protected String wellKnown;
    protected String clientId;
    protected boolean cache;

    protected static AuthorizationServerMetadata metadata;
    protected static JWSHeader header;

    protected final MaskinportenGateway gateway = new MaskinportenGateway();

    public abstract String getAccessToken(String... scopes);

    protected static AuthorizationServerMetadata getMetadata(String wellKnown) {
        try {
            return AuthorizationServerMetadata.resolve(new Issuer(wellKnown));
        } catch (GeneralException | IOException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    protected JWTClaimsSet createJWTClaimsSet(String audience, String issuer, String... scopes) {
        return new JWTClaimsSet.Builder()
                .audience(audience)
                .issuer(issuer)
                .claim("scope", String.join(" ", scopes))
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date(Clock.systemUTC().millis()))
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000))
                .build();
    }
}