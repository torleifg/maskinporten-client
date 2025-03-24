package com.github.torleifg.maskinporten;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.io.IOException;
import java.text.ParseException;
import java.time.Clock;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public abstract class MaskinportenClient {
    protected String wellKnown;
    protected String clientId;
    protected boolean cache;

    protected AuthorizationServerMetadata metadata;
    protected JWSHeader header;
    protected RSASSASigner signer;

    private final MaskinportenGateway gateway = new MaskinportenGateway();

    private final Map<String, String> accessTokens = new ConcurrentHashMap<>();

    public Optional<String> getAccessToken(String... scopes) throws MaskinportenClientException {
        if (cache) {
            return getCachedAccessToken(scopes);
        }

        return gateway.getJwtGrantResponse(createJwtGrant(scopes), metadata.getTokenEndpointURI())
                .map(JwtGrantResponse::accessToken);
    }

    private Optional<String> getCachedAccessToken(String... scopes) {
        var key = String.join(" ", scopes);
        var accessToken = accessTokens.get(key);

        if (accessToken == null) {
            var jwtGrant = createJwtGrant(scopes);
            var token = gateway.getJwtGrantResponse(jwtGrant, metadata.getTokenEndpointURI())
                    .map(JwtGrantResponse::accessToken);
            token.ifPresent(value -> accessTokens.put(key, value));

            return token;
        }

        try {
            var jwt = JWTParser.parse(accessToken);
            var expiration = jwt.getJWTClaimsSet().getExpirationTime();
            var current = new Date(Clock.systemUTC().millis() - 10000);

            if (current.compareTo(expiration) >= 0) {
                var jwtGrant = createJwtGrant(scopes);
                var token = gateway.getJwtGrantResponse(jwtGrant, metadata.getTokenEndpointURI())
                        .map(JwtGrantResponse::accessToken);
                token.ifPresent(value -> accessTokens.put(key, value));

                return token;
            }

        } catch (ParseException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }

        return Optional.of(accessToken);
    }

    private String createJwtGrant(String... scopes) {
        var claimsSet = createJWTClaimsSet(metadata.getIssuer().getValue(), clientId, scopes);
        var jwt = new SignedJWT(header, claimsSet);

        try {
            jwt.sign(signer);
            return jwt.serialize();

        } catch (JOSEException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    protected static AuthorizationServerMetadata getMetadata(String wellKnown) {
        try {
            return AuthorizationServerMetadata.resolve(new Issuer(wellKnown), 2000, 30000);
        } catch (GeneralException | IOException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    private JWTClaimsSet createJWTClaimsSet(String audience, String issuer, String... scopes) {
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