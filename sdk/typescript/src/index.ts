/**
 * Loom TypeScript SDK — thin HTTP client. Server enforces all policy.
 */

export interface Denial {
  Reason?: string;
  Message?: string;
  Step?: string;
  Retryable?: boolean;
  Hint?: string;
  Details?: Record<string, string> | null;
  // snake_case variants if a gateway rewrites
  reason?: string;
  message?: string;
  step?: string;
  retryable?: boolean;
  hint?: string;
}

export interface Response {
  Allowed: boolean;
  Decision: string;
  Denial?: Denial | null;
  Output?: Record<string, unknown> | null;
  TraceID?: string;
  AuditID?: string;
  IdempotentReplay?: boolean;
  Risk?: string;
  Outcome?: string;
  ExecutionID?: string;
  OperationVersion?: string;
  ReliabilityWarning?: string;
}

export interface ResourceRef {
  type: string;
  id: string;
}

export interface CallOptions {
  operation: string;
  operationVersion?: string;
  boundary: string;
  input?: Record<string, unknown>;
  resource?: ResourceRef;
  fields?: string[];
  idempotencyKey?: string;
  approvalToken?: string;
  token?: string;
  metadata?: Record<string, string>;
  traceId?: string;
}

export class Client {
  constructor(
    public readonly baseUrl: string,
    public readonly token: string = "",
    public readonly fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}

  async call(opts: CallOptions): Promise<Response> {
    const url = `${this.baseUrl.replace(/\/$/, "")}/v1/execute`;
    const body = {
      operation: opts.operation,
      operation_version: opts.operationVersion,
      boundary: opts.boundary,
      input: opts.input ?? {},
      fields: opts.fields,
      idempotency_key: opts.idempotencyKey,
      approval_token: opts.approvalToken,
      resource: opts.resource
        ? { type: opts.resource.type, id: opts.resource.id }
        : undefined,
      metadata: { adapter: "sdk-typescript", ...(opts.metadata ?? {}) },
    };
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Loom-Protocol-Version": "1",
			"User-Agent": "loom-typescript-sdk/1.0.1",
    };
    const bearer = opts.token ?? this.token;
    if (bearer) headers["Authorization"] = `Bearer ${bearer}`;
    if (opts.traceId) headers["X-Trace-Id"] = opts.traceId;

    const res = await this.fetchImpl(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const text = await res.text();
    try {
      return JSON.parse(text) as Response;
    } catch {
      return {
        Allowed: false,
        Decision: "deny",
        Denial: {
          Reason: "internal",
          Message: "invalid json response",
          Step: "sdk",
        },
      };
    }
  }

  /** GET /.well-known/loom.json — unauthenticated discovery. */
  async manifest(): Promise<Record<string, unknown>> {
    return this.getJson("/.well-known/loom.json", false);
  }

  /** GET /v1/openapi.json — capability-filtered OpenAPI. */
  async openapi(token?: string): Promise<Record<string, unknown>> {
    return this.getJson("/v1/openapi.json", true, token);
  }

  /** Governed catalog.spec call. */
  async catalogSpec(boundary: string, token?: string): Promise<Response> {
    return this.call({
      operation: "catalog.spec",
      boundary,
      input: {},
      token,
    });
  }

  /** POST /mcp — one JSON-RPC MCP message. */
  async mcp(
    rpc: Record<string, unknown>,
    token?: string,
  ): Promise<Record<string, unknown>> {
    const url = `${this.baseUrl.replace(/\/$/, "")}/mcp`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
			"User-Agent": "loom-typescript-sdk/1.0.1",
      "X-Loom-Protocol-Version": "1",
    };
    const bearer = token ?? this.token;
    if (bearer) headers["Authorization"] = `Bearer ${bearer}`;
    const res = await this.fetchImpl(url, {
      method: "POST",
      headers,
      body: JSON.stringify(rpc),
    });
    if (res.status === 204) return {};
    const text = await res.text();
    if (!text.trim()) return {};
    return JSON.parse(text) as Record<string, unknown>;
  }

  private async getJson(
    path: string,
    auth: boolean,
    token?: string,
  ): Promise<Record<string, unknown>> {
    const url = `${this.baseUrl.replace(/\/$/, "")}${path}`;
    const headers: Record<string, string> = {
			"User-Agent": "loom-typescript-sdk/1.0.1",
      "X-Loom-Protocol-Version": "1",
    };
    if (auth) {
      const bearer = token ?? this.token;
      if (bearer) headers["Authorization"] = `Bearer ${bearer}`;
    }
    const res = await this.fetchImpl(url, { method: "GET", headers });
    return (await res.json()) as Record<string, unknown>;
  }
}

/** Helper: agent-actionable fields from a Denial (PascalCase or snake_case). */
export function denialHint(d?: Denial | null): string {
  if (!d) return "";
  return d.Hint ?? d.hint ?? "";
}

export function denialRetryable(d?: Denial | null): boolean {
  if (!d) return false;
  return Boolean(d.Retryable ?? d.retryable);
}
