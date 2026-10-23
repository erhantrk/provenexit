/** Host-level failures of the mock TDX host. Messages are static codes. */
export class HostError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "HostError";
  }
}
