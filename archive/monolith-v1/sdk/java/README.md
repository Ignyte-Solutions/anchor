# Java SDK (Ignyte Anchor)

Location: `sdk/java/IgnyteAnchorClient.java`

## What it provides

- `issueCapability(String requestJson)`
- `verifyAction(String requestJson)`

Both methods send JSON to the Ignyte Anchor API and return the raw JSON response body.

## Requirements

- Java 11+

## Usage

```java
import com.ignyte.anchor.sdk.IgnyteAnchorClient;

public final class Example {
    public static void main(String[] args) throws Exception {
        IgnyteAnchorClient client = IgnyteAnchorClient.withDefaultHttpClient("http://localhost:8080");

        String issueRequest = """
            {
              "agent_public_key": "BASE64_ED25519_PUBLIC_KEY",
              "allowed_actions": ["s3:PutObject"],
              "constraints": {
                "resource_limits": {"s3:objects": 10},
                "spend_limits": {"usd_cents": 1000},
                "api_scopes": ["aws:s3"],
                "rate_limits": {"requests_per_minute": 30},
                "environment_constraints": ["prod"]
              },
              "expires_at": "2026-02-13T10:00:00Z"
            }
            """;

        String issueResponse = client.issueCapability(issueRequest);
        System.out.println(issueResponse);
    }
}
```

Use your preferred JSON library (Jackson, Gson, etc.) in the consuming application to build/parse request and response payloads.
