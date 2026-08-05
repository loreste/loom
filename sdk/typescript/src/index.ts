/**
 * Loom TypeScript SDK — thin HTTP client. Server enforces all policy.
 */

export interface Denial {
  Reason?: string;
  Message?: string;
  Step?: string;
  Details?: Record<string, string> | null;
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
}

export interface ResourceRef {
  type: string;
  id: string;
}

export interface CallOptions {
  operation: string;
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
      "User-Agent": "loom-typescript-sdk/0.3",
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
          Message: `invalid json (${res.status})`,
          Step: "sdk",
        },
      };
    }
  }
}
