package com.github.torleifg.maskinporten;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;

import java.io.IOException;

public abstract class MaskinportenClient {

    public abstract String getAccessToken(String... scopes);

    protected static AuthorizationServerMetadata getMetadata(String wellKnown) {
        try {
            return AuthorizationServerMetadata.resolve(new Issuer(wellKnown));
        } catch (GeneralException | IOException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }
}