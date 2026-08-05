import { Client, type Response } from "./index.js";

export interface NodeClientOptions {
  /** Override fetch for tests or Node versions without global fetch. */
  fetchImpl?: typeof fetch;
}

/** Node-friendly client for Node 18+ applications. */
export class NodeClient extends Client {
  constructor(baseUrl: string, token = "", options: NodeClientOptions = {}) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) {
      throw new Error("NodeClient requires Node 18+ global fetch or options.fetchImpl");
    }
    super(baseUrl, token, fetchImpl);
  }
}

export type { Response };
