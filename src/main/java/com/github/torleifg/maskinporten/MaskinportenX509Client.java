package com.github.torleifg.maskinporten;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class MaskinportenX509Client extends MaskinportenClient {
    private X509Certificate certificate;
    private PrivateKey key;

    private MaskinportenX509Client() {
    }

    public static Client builder() {
        return new Builder();
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
            requireNonNull(wellKnown, "wellKnown must not be null");
            client.wellKnown = wellKnown;
            return this;
        }

        @Override
        public ClientId clientId(String clientId) {
            requireNonNull(clientId, "clientId must not be null");
            client.clientId = clientId;
            return this;
        }

        @Override
        public Certificate certificate(X509Certificate certificate) {
            requireNonNull(certificate, "certificate must not be null");
            client.certificate = certificate;
            return this;
        }

        @Override
        public Key key(PrivateKey key) {
            requireNonNull(key, "key must not be null");
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
            client.metadata = getMetadata(client.wellKnown);

            try {
                var certChain = List.of(Base64.encode(client.certificate.getEncoded()));

                client.header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .x509CertChain(certChain)
                        .build();

                client.signer = new RSASSASigner(client.key);

            } catch (CertificateEncodingException e) {
                throw new MaskinportenClientException(e.getMessage(), e);
            }

            return client;
        }
    }
}