export type CapabilityConstraints = {
  resource_limits: Record<string, number>;
  spend_limits: Record<string, number>;
  api_scopes: string[];
  rate_limits: Record<string, number>;
  environment_constraints: string[];
};

export type Capability = {
  version: number;
  capability_id: string;
  issuer_id: string;
  agent_id: string;
  allowed_actions: string[];
  constraints: CapabilityConstraints;
  issued_at: string;
  expires_at: string;
  nonce: string;
  signature: string;
};

export type ConstraintEvidence = {
  resource_usage: Record<string, number>;
  spend_usage: Record<string, number>;
  rate_usage: Record<string, number>;
  environment: string;
  api_scope: string;
};

export type ActionEnvelope = {
  action_id: string;
  agent_id: string;
  capability_id: string;
  action_type: string;
  action_payload: unknown;
  constraint_evidence: ConstraintEvidence;
  timestamp: string;
  agent_signature: string;
};

export type IssueCapabilityRequest = {
  agent_public_key: string;
  allowed_actions: string[];
  constraints: CapabilityConstraints;
  expires_at: string;
  nonce?: string;
};

export type IssueCapabilityResponse = {
  capability: Capability;
  issuer: {
    issuer_id: string;
    public_key: string;
    metadata?: Record<string, string>;
  };
};

export type VerifyActionRequest = {
  capability: Capability;
  action: ActionEnvelope;
  issuer_public_key: string;
  agent_public_key: string;
  revoked_capability_ids: string[];
};

export type VerificationResult = {
  decision: "AUTHORIZED" | "REJECTED";
  reasons: string[];
};

export class IgnyteAnchorClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;

  constructor(baseUrl: string, fetchFn: typeof fetch) {
    if (!baseUrl || baseUrl.trim().length === 0) {
      throw new Error("baseUrl is required");
    }
    if (!fetchFn) {
      throw new Error("fetchFn is required");
    }
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetchFn = fetchFn;
  }

  async issueCapability(request: IssueCapabilityRequest): Promise<IssueCapabilityResponse> {
    const response = await this.fetchFn(`${this.baseUrl}/v1/capabilities`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    if (response.status !== 201) {
      throw new Error(`Issue capability failed (${response.status}): ${await response.text()}`);
    }
    return (await response.json()) as IssueCapabilityResponse;
  }

  async verifyAction(request: VerifyActionRequest): Promise<VerificationResult> {
    const response = await this.fetchFn(`${this.baseUrl}/v1/actions/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    if (response.status !== 200) {
      throw new Error(`Verify action failed (${response.status}): ${await response.text()}`);
    }
    return (await response.json()) as VerificationResult;
  }
}
