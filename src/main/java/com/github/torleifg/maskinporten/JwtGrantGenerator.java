package com.github.torleifg.maskinporten;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.util.*;

class JwtGrantGenerator {

    public static String createJwtGrant(String audience, String issuer, String jwks, String kid, String... scopes) {
        try {
            var jwkSet = JWKSet.parse(jwks);
            var jwk = jwkSet.getKeyByKeyId(kid);

            if (jwk == null) {
                throw new MaskinportenClientException("Invalid kid. Must match kid in JWKS.");
            }

            var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(kid)
                    .build();

            var claimSet = getClaimsSet(audience, issuer, scopes);

            var jwt = new SignedJWT(header, claimSet);
            jwt.sign(new RSASSASigner(jwk.toRSAKey()));

            return jwt.serialize();
        } catch (JOSEException | ParseException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    public static String createJwtGrant(String audience, String issuer, X509Certificate certificate, PrivateKey key, String... scopes) {
        try {
            var certChain = List.of(Base64.encode(certificate.getEncoded()));

            var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(certChain)
                    .build();

            var claimSet = getClaimsSet(audience, issuer, scopes);

            var jwt = new SignedJWT(header, claimSet);
            jwt.sign(new RSASSASigner(key));

            return jwt.serialize();
        } catch (JOSEException | CertificateEncodingException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    private static JWTClaimsSet getClaimsSet(String audience, String issuer, String... scopes) {
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