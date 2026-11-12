/** Real Intel TDX quotes from the dstack guest agent (SPEC-TDX §4.2). */
import { DstackClient } from "@phala/dstack-sdk";
import { fromHex, PlrError, type Attester, type TdxEvent } from "@plr/shared";

export class DstackAttester implements Attester {
  readonly #c: DstackClient;
  constructor(endpoint = "/var/run/dstack.sock") {
    this.#c = new DstackClient(endpoint);
  }

  async getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }> {
    if (!(reportData instanceof Uint8Array) || reportData.length !== 64) throw new PlrError("E_BAD_INPUT", "report_data");
    const r = await this.#c.getQuote(reportData); // raw 64 bytes, no hashing (sdk: hex.length ≤ 128)
    const quote = fromHex(String(r.quote).replace(/^0x/, ""));
    const all = JSON.parse(r.event_log) as Array<Record<string, unknown>>;
    const eventLog = all
      .filter((e) => e.imr === 3)
      .map((e) => ({
        imr: 3,
        event_type: e.event_type as number,
        digest: String(e.digest),
        event: String(e.event),
        event_payload: String(e.event_payload),
      }));
    return { quote, eventLog };
  }

  /** The measured dstack app-compose, exactly as dstack hashed it. */
  async appCompose(): Promise<string> {
    const i = await this.#c.info();
    return i.tcb_info.app_compose;
  }
}
