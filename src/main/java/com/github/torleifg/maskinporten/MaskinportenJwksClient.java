package com.github.torleifg.maskinporten;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

public class MaskinportenJwksClient extends MaskinportenClient {
    protected String jwks;
    protected String kid;

    protected static JWK jwk;

    private MaskinportenJwksClient() {
    }

    public static Client builder() {
        return new Builder();
    }

    @Override
    public String getAccessToken(String... scopes) {
        var claimsSet = createJWTClaimsSet(metadata.getIssuer().getValue(), clientId, scopes);
        var jwt = new SignedJWT(header, claimsSet);

        try {
            jwt.sign(new RSASSASigner(jwk.toRSAKey()));

            return gateway.getAccessToken(jwt.serialize(), metadata.getTokenEndpointURI());
        } catch (JOSEException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    public interface Client {
        WellKnown wellKnown(String wellKnown);
    }

    public interface WellKnown {
        ClientId clientId(String clientId);
    }

    public interface ClientId {
        Jwks jwks(String jwks);
    }

    public interface Jwks {
        Kid kid(String kid);
    }

    public interface Kid {
        Cache cache(boolean cache);
    }

    public interface Cache {
        MaskinportenClient build();
    }

    private static class Builder implements Client, WellKnown, ClientId, Jwks, Kid, Cache {
        final MaskinportenJwksClient client = new MaskinportenJwksClient();

        @Override
        public WellKnown wellKnown(String wellKnown) {
            client.wellKnown = wellKnown;
            return this;
        }

        @Override
        public ClientId clientId(String clientId) {
            client.clientId = clientId;
            return this;
        }

        @Override
        public Jwks jwks(String jwks) {
            client.jwks = jwks;
            return this;
        }

        @Override
        public Kid kid(String kid) {
            client.kid = kid;
            return this;
        }

        @Override
        public Cache cache(boolean cache) {
            client.cache = cache;
            return this;
        }

        @Override
        public MaskinportenClient build() {
            metadata = getMetadata(client.wellKnown);

            try {
                var jwkSet = JWKSet.parse(client.jwks);
                jwk = jwkSet.getKeyByKeyId(client.kid);

                if (jwk == null) {
                    throw new MaskinportenClientException("Invalid kid. Must match kid in JWKS.");
                }

                header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(client.kid)
                        .build();

            } catch (ParseException e) {
                throw new MaskinportenClientException(e.getMessage(), e);
            }

            return client;
        }
    }
}