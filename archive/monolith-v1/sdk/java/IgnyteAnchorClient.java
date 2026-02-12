package com.ignyte.anchor.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public final class IgnyteAnchorClient {
    private final String baseUrl;
    private final HttpClient httpClient;

    public IgnyteAnchorClient(String baseUrl, HttpClient httpClient) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        if (httpClient == null) {
            throw new IllegalArgumentException("httpClient is required");
        }
        this.baseUrl = stripTrailingSlash(baseUrl.trim());
        this.httpClient = httpClient;
    }

    public static IgnyteAnchorClient withDefaultHttpClient(String baseUrl) {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
        return new IgnyteAnchorClient(baseUrl, client);
    }

    public String issueCapability(String issueCapabilityRequestJson) throws IOException, InterruptedException {
        return postJson("/v1/capabilities", issueCapabilityRequestJson, 201, "Issue capability");
    }

    public String verifyAction(String verifyActionRequestJson) throws IOException, InterruptedException {
        return postJson("/v1/actions/verify", verifyActionRequestJson, 200, "Verify action");
    }

    private String postJson(String path, String requestJson, int expectedStatus, String operation)
        throws IOException, InterruptedException {
        if (requestJson == null || requestJson.trim().isEmpty()) {
            throw new IllegalArgumentException("requestJson is required");
        }

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestJson))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != expectedStatus) {
            throw new IOException(
                operation + " failed (" + response.statusCode() + "): " + response.body()
            );
        }
        return response.body();
    }

    private static String stripTrailingSlash(String value) {
        if (value.endsWith("/")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }
}
