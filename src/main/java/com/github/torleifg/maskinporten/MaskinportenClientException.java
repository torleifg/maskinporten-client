package com.github.torleifg.maskinporten;

public class MaskinportenClientException extends RuntimeException {

    public MaskinportenClientException(String message) {
        super(message);
    }

    public MaskinportenClientException(String message, Throwable cause) {
        super(message, cause);
    }
}