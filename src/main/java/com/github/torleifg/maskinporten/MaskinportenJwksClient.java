package com.github.torleifg.maskinporten;

import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

public class MaskinportenJwksClient extends MaskinportenClient {
    AuthorizationServerMetadata metadata;
    String clientId;
    String jwks;
    String kid;
    boolean cache;

    final MaskinportenGateway gateway = new MaskinportenGateway();

    private MaskinportenJwksClient() {
    }

    public static Client builder() {
        return new Builder();
    }

    @Override
    public String getAccessToken(String... scopes) {
        var jwtGrant = JwtGrantGenerator.createJwtGrant(metadata.getIssuer().getValue(), clientId, jwks, kid, scopes);

        return gateway.getAccessToken(jwtGrant, metadata.getTokenEndpointURI());
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
            client.metadata = getMetadata(wellKnown);
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
            return client;
        }
    }
}