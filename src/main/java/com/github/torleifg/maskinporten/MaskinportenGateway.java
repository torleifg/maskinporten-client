package com.github.torleifg.maskinporten;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

class MaskinportenGateway {
    private final HttpClient client;
    private final Gson gson;

    MaskinportenGateway() {
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();

        this.gson = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .create();
    }

    Optional<JwtGrantResponse> getJwtGrantResponse(String jwtGrant, URI tokenEndpoint) {
        var data = Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion", jwtGrant
        );

        var request = HttpRequest.newBuilder()
                .POST(createForm(data))
                .uri(tokenEndpoint)
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();

        try {
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return Optional.ofNullable(gson.fromJson(response.body(), JwtGrantResponse.class));
            }

            throw new MaskinportenClientException(String.format("%s %s %s", response.request(), response.statusCode(), response.body()));

        } catch (InterruptedException | JsonSyntaxException | IOException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    private HttpRequest.BodyPublisher createForm(Map<String, String> data) {
        var builder = new StringBuilder();

        data.forEach((key, value) -> {
            if (!builder.isEmpty()) {
                builder.append("&");
            }
            builder.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            builder.append("=");
            builder.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });

        return HttpRequest.BodyPublishers.ofString(builder.toString());
    }
}