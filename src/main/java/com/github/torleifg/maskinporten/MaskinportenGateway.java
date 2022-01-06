package com.github.torleifg.maskinporten;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

class MaskinportenGateway {
    private final HttpClient client;
    private final Gson gson;

    public MaskinportenGateway() {
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();

        this.gson = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .create();
    }

    public String getAccessToken(String jwtGrant, URI tokenEndpoint) {
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
                var token = gson.fromJson(response.body(), JwtGrantResponse.class);
                return token.getAccessToken();
            }

            throw new MaskinportenClientException(response.body());

        } catch (InterruptedException | IOException e) {
            throw new MaskinportenClientException(e.getMessage(), e);
        }
    }

    private HttpRequest.BodyPublisher createForm(Map<String, String> data) {
        var builder = new StringBuilder();

        data.forEach((key, value) -> {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            builder.append("=");
            builder.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });

        return HttpRequest.BodyPublishers.ofString(builder.toString());
    }
}