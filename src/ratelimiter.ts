/**
 * Durable Object: RateLimiter
 *
 * Each instance is keyed by IP address.
 * Enforces 5 requests per 600 seconds (10 minutes).
 */
export class RateLimiter implements DurableObject {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const now = Date.now();
    const windowMs = 600_000; // 10 minutes
    const maxPoints = 5;

    // Load existing timestamps for this IP
    let timestamps: number[] =
      (await this.state.storage.get<number[]>("ts")) ?? [];

    // Discard timestamps outside the current window
    timestamps = timestamps.filter((t) => now - t < windowMs);

    if (timestamps.length >= maxPoints) {
      return new Response("rate_limited", { status: 429 });
    }

    timestamps.push(now);
    await this.state.storage.put("ts", timestamps);

    return new Response("ok", { status: 200 });
  }
}
