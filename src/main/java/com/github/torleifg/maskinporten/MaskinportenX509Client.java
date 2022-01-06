package com.github.torleifg.maskinporten;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class MaskinportenX509Client extends MaskinportenClient {
    protected X509Certificate certificate;
    protected PrivateKey key;

    private MaskinportenX509Client() {
    }

    public static Client builder() {
        return new Builder();
    }

    @Override
    public String getAccessToken(String... scopes) {
        var jwtGrant = JwtGrantGenerator.createJwtGrant(metadata.getIssuer().getValue(), clientId, certificate, key, scopes);

        return gateway.getAccessToken(jwtGrant, metadata.getTokenEndpointURI());
    }

    public interface Client {
        WellKnown wellKnown(String wellKnown);
    }

    public interface WellKnown {
        ClientId clientId(String clientId);
    }

    public interface ClientId {
        Certificate certificate(X509Certificate certificate);
    }

    public interface Certificate {
        Key key(PrivateKey key);
    }

    public interface Key {
        Cache cache(boolean cache);
    }

    public interface Cache {
        MaskinportenClient build();
    }

    private static class Builder implements Client, WellKnown, ClientId, Certificate, Key, Cache {
        final MaskinportenX509Client client = new MaskinportenX509Client();

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
        public Certificate certificate(X509Certificate certificate) {
            client.certificate = certificate;
            return this;
        }

        @Override
        public Key key(PrivateKey key) {
            client.key = key;
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