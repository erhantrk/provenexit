// In-process fake PLR-VPN exit (SPEC-VPN §3–§5) built only from @plr/shared primitives + MemoryRegistry, plus a
// local HTTP destination. Misbehaviours are switchable per test. The fake records what it saw only so tests can
// assert on it (a real exit must not). Several fakes may share one root + registry (two-hop tests).
import { createServer, type Server, type IncomingMessage } from "node:http";
import { connect as tcpConnect, isIP, type AddressInfo, type Socket } from "node:net";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import {
  FRAME,
  TUNNEL,
  MockRoot,
  MockTdxAttester,
  MemoryRegistry,
  TunnelReader,
  TunnelWriter,
  encodeConnectErr,
  encodeReceiptPayload,
  keyHash,
  merkleProof,
  merkleRoot,
  mockOsReport,
  osMeasurement,
  parseConnect,
  parseHello,
  deriveTunnel,
  encodeServerHello,
  signVpnReceipt,
  toHex,
  fromHex,
  tunnelServerAccept,
  vpnReceiptLeaf,
  type AttestationBundle,
  type ConnectErrCode,
  type InstanceRecord,
  type VpnReceipt,
  registrationReportData,
  reportData,
} from "@plr/shared";

/** report_data a fake quotes for `nonce`: the §5 rev 1.3 session value unless a misbehaviour picks another purpose. */
export function quoteReportData(
  purpose: "raw-nonce" | "registration" | undefined,
  xp: Uint8Array,
  ep: Uint8Array,
  nonce: Uint8Array,
  reg: { contractId: string; operator: string },
): Uint8Array {
  if (purpose === "raw-nonce") {
    const rd = new Uint8Array(64);
    rd.set(keyHash(xp, ep), 0);
    rd.set(nonce, 32);
    return rd;
  }
  if (purpose === "registration") return registrationReportData(xp, ep, reg.contractId, reg.operator);
  return reportData(xp, ep, nonce);
}

export const vpnCompose = (bundleSha = "33".repeat(32)): string =>
  JSON.stringify(
    {
      manifest_version: 1,
      name: "plr-vpn",
      policy: { disk: "none", egress: { allow_loopback: true, deny_private: true }, logs: "none" },
      vpn: { bundle_sha256: bundleSha, entry: "vpn.bundle.mjs", node_sha256: "44".repeat(32) },
    },
    null,
    2,
  ) + "\n";
export const VPN_COMPOSE = vpnCompose();

/** Anchors added by fakes per registry (several fakes may share one registry; anchor ids are global). */
const anchorCounts = new WeakMap<MemoryRegistry, number>();

export interface ExitBehaviour {
  /** Advertise a different x25519 key than the one the quote binds. */
  mitmKey?: boolean;
  /** Replay the first attestation bundle for every nonce. */
  replayAttestation?: boolean;
  /** Quote a report_data of another purpose than §5 rev 1.3 session ({@link quoteReportData}). */
  quotePurpose?: "raw-nonce" | "registration";
  /** Answer every CONNECT with this CONNECT_ERR code. */
  connectErr?: ConnectErrCode;
  /** Raw CONNECT_ERR payload (protocol abuse). */
  rawConnectErr?: Uint8Array;
  /** Flip one ciphertext byte of the first s2c DATA frame. */
  tamperFirstData?: boolean;
  /** Forward CONNECT_OK and the first s2c DATA frame, then close the socket (no FIN). */
  truncateAfterFirstData?: boolean;
  /** Like truncate, but cut in the middle of the first DATA frame. */
  cutMidFrame?: boolean;
  /** Close after both FINs without sending RECEIPT. */
  noReceipt?: boolean;
  /** Sign the receipt with a different key. */
  wrongSigner?: boolean;
  /** Mutate the receipt before (correctly) signing it. */
  mutateReceipt?: (r: VpnReceipt) => VpnReceipt;
  /** Send a DATA frame before CONNECT_OK. */
  dataBeforeOk?: boolean;
  /** Reply to the upgrade with this HTTP status instead of 101. */
  upgradeStatus?: number;
  /** Bytes to stream to the client after CONNECT_OK instead of relaying the upstream (then FIN). */
  blast?: number;
  /** Send `101 ‖ server_hello` in one write, before the hello arrives (precomputed exit ephemeral). */
  serverHelloInHead?: boolean;
  /** Send the server_hello one byte at a time. */
  dribbleServerHello?: boolean;
  /** Replace the server_hello by these bytes. */
  rawServerHello?: Uint8Array;
  /** Never send the server_hello (count what the client sends meanwhile). */
  withholdServerHello?: boolean;
  /** Send the server_hello glued to an (authentic) unsolicited DATA frame in one write. */
  dataAfterServerHello?: boolean;
}

export interface FakeExit {
  url: string;
  root: MockRoot;
  registry: MemoryRegistry;
  composeHash: string;
  keyHash: string;
  osHash: string;
  record: InstanceRecord;
  behaviour: ExitBehaviour;
  /** Fake exit-side DNS: name → IP (the client must never resolve these). */
  dns: Map<string, string>;
  stats: { attestations: number; tunnels: number; connects: number; maxC2sPayload: number; blastSent: number; destinations: string[]; hellos: string[]; bytesWithoutServerHello: number };
  receipts: VpnReceipt[];
  /** Anchors every receipt so far as one batch on the registry (first_seq = registry next_seq). */
  anchorAll(): void;
  close(): Promise<void>;
}

const enc = new TextEncoder();

export interface FakeExitOptions {
  /** Share an attestation root (two-hop: both hops under one pinned root). */
  root?: MockRoot;
  /** Share a registry: the exit adds its compose / OS / instance to it. */
  registry?: MemoryRegistry;
  /** Operator account of the instance (default `vpn-operator.test.near`). */
  operator?: string;
  /** Another build: `vpn.bundle_sha256` of the compose (default 33…33). */
  bundleSha?: string;
  /** Measured compose text instead of the default `plr-vpn` one. */
  composeText?: string;
}

export async function startFakeExit(o: FakeExitOptions = {}): Promise<FakeExit> {
  const root = o.root ?? MockRoot.generate();
  const composeText = o.composeText ?? vpnCompose(o.bundleSha);
  const composeBytes = enc.encode(composeText);
  const attester = new MockTdxAttester({ root, composeBytes });
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  const kh = toHex(keyHash(xp, ep));
  const composeHash = toHex(sha256(composeBytes));
  const osHash = toHex(osMeasurement(mockOsReport()));
  const record: InstanceRecord = {
    compose_hash: composeHash,
    os_measurement: osHash,
    x25519: toHex(xp),
    ed25519: toHex(ep),
    operator: o.operator ?? "vpn-operator.test.near",
    org_id: null,
    registered_at_ms: 1,
    expires_at_ms: Date.now() + 3_600_000,
    next_seq: 0,
  };
  let registry: MemoryRegistry;
  if (o.registry !== undefined) {
    registry = o.registry;
    registry.allowCompose(composeHash);
    registry.allowOs(osHash);
    registry.putInstance(kh, record);
  } else {
    registry = new MemoryRegistry({
      root: { kind: "MOCK", p256: toHex(root.publicKey) },
      compose: [composeHash],
      os: [osHash],
      instances: { [kh]: record },
    });
  }
  const behaviour: ExitBehaviour = {};
  const dns = new Map<string, string>();
  const stats = { attestations: 0, tunnels: 0, connects: 0, maxC2sPayload: 0, blastSent: 0, destinations: [] as string[], hellos: [] as string[], bytesWithoutServerHello: 0 };
  const receipts: VpnReceipt[] = [];
  const anchored: { firstSeq: number; count: number; anchorId: number }[] = [];
  let firstBundle: AttestationBundle | undefined;
  const sockets = new Set<Socket>();

  const json = (res: import("node:http").ServerResponse, status: number, body: unknown): void => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://exit");
      if (req.method === "GET" && url.pathname === "/v1/attestation") {
        const nonceHex = url.searchParams.get("nonce") ?? "";
        if (!/^[0-9a-f]{64}$/.test(nonceHex)) return json(res, 400, { error: "E_BAD_REQUEST" });
        stats.attestations++;
        if (behaviour.replayAttestation && firstBundle) return json(res, 200, firstBundle);
        const { quote, eventLog } = await attester.getQuote(quoteReportData(behaviour.quotePurpose, xp, ep, fromHex(nonceHex, 32), { contractId: "vpnregistry.test.near", operator: record.operator }));
        const bundle: AttestationBundle = {
          v: "PLR-v1",
          root_kind: "MOCK",
          quote: toHex(quote),
          event_log: eventLog,
          app_compose: composeText,
          x25519: behaviour.mitmKey ? toHex(x25519.getPublicKey(x25519.utils.randomSecretKey())) : toHex(xp),
          ed25519: toHex(ep),
        };
        firstBundle ??= bundle;
        return json(res, 200, bundle);
      }
      if (req.method === "GET" && url.pathname === "/v1/receipts/proof") {
        const seq = Number(url.searchParams.get("seq"));
        const batch = anchored.find((a) => seq >= a.firstSeq && seq < a.firstSeq + a.count);
        if (!batch) return json(res, 404, { error: "E_NOT_ANCHORED" });
        const leaves = receipts.slice(batch.firstSeq, batch.firstSeq + batch.count).map(vpnReceiptLeaf);
        const index = seq - batch.firstSeq;
        return json(res, 200, {
          anchor_id: batch.anchorId,
          first_seq: batch.firstSeq,
          count: batch.count,
          index,
          root: toHex(merkleRoot(leaves)),
          proof: merkleProof(leaves, index).map(toHex),
        });
      }
      if (url.pathname === "/v1/tunnel") return json(res, 400, { error: "E_BAD_REQUEST" });
      if (url.pathname === "/healthz") return json(res, 200, { ok: true });
      return json(res, 404, { error: "E_BAD_REQUEST" });
    })();
  });

  server.on("upgrade", (req: IncomingMessage, socket: Socket, head: Buffer) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    if (req.url !== "/v1/tunnel" || (req.headers.upgrade ?? "").toLowerCase() !== "plr-vpn/1") {
      socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
      return;
    }
    if (behaviour.upgradeStatus !== undefined) {
      socket.end(`HTTP/1.1 ${behaviour.upgradeStatus} Nope\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
      return;
    }
    stats.tunnels++;
    tunnel(socket, new Uint8Array(head));
  });

  const UPGRADED = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: plr-vpn/1\r\n\r\n";

  function tunnel(sock: Socket, head: Uint8Array): void {
    const b = { ...behaviour };
    // Early server_hello: the exit ephemeral does not depend on the client hello, so it can go out with the 101.
    let early: { ess: Uint8Array; epkS: Uint8Array } | undefined;
    if (b.serverHelloInHead) {
      const ess = x25519.utils.randomSecretKey();
      early = { ess, epkS: x25519.getPublicKey(ess) };
      sock.write(Buffer.concat([Buffer.from(UPGRADED), encodeServerHello(early.epkS)]));
    } else sock.write(UPGRADED);
    const sendServerHello = (sh: Uint8Array, then?: Uint8Array): void => {
      const bytes = b.rawServerHello ?? sh;
      if (b.dribbleServerHello) {
        let i = 0;
        const tick = (): void => {
          if (sock.destroyed) return;
          if (i < bytes.length) {
            sock.write(bytes.subarray(i, ++i));
            setImmediate(tick);
          } else if (then) sock.write(then);
        };
        tick();
        return;
      }
      sock.write(then ? Buffer.concat([bytes, then]) : bytes);
    };
    const tsOpen = Date.now();
    let hello = new Uint8Array(0);
    let reader: TunnelReader | undefined;
    let writer: TunnelWriter | undefined;
    let th: Uint8Array | undefined;
    let upstream: Socket | undefined;
    let c2sFin = false;
    let s2cFin = false;
    let dataSent = 0;
    let connected = false;

    const send = (type: number, payload: Uint8Array): void => {
      if (sock.destroyed) return;
      const wire = writer!.seal(type, payload);
      if (type === FRAME.DATA) {
        dataSent++;
        if (dataSent === 1 && b.tamperFirstData) wire[wire.length - 20]! ^= 0x01;
        if (dataSent === 1 && b.cutMidFrame) {
          sock.end(wire.subarray(0, 10));
          return;
        }
      }
      sock.write(wire);
      if (type === FRAME.DATA && dataSent === 1 && b.truncateAfterFirstData) sock.end();
    };
    const maybeReceipt = (): void => {
      if (!c2sFin || !s2cFin) return;
      if (b.noReceipt) {
        sock.end();
        return;
      }
      let r: VpnReceipt = {
        v: 1, th: toHex(th!), compose_hash: composeHash, key_hash: kh, seq: receipts.length, ts_open_ms: tsOpen, ts_close_ms: Date.now(),
      };
      if (b.mutateReceipt) r = b.mutateReceipt(r);
      receipts.push(r);
      const sig = signVpnReceipt(r, b.wrongSigner ? ed25519.utils.randomSecretKey() : es);
      send(FRAME.RECEIPT, encodeReceiptPayload({ receipt: r, sig }));
      sock.end();
    };
    const sendData = (buf: Uint8Array): void => {
      for (let off = 0; off < buf.length; off += TUNNEL.MAX_PAYLOAD) send(FRAME.DATA, buf.subarray(off, off + TUNNEL.MAX_PAYLOAD));
    };
    const onConnect = (host: string, port: number): void => {
      stats.connects++;
      stats.destinations.push(`${host}:${port}`);
      if (b.rawConnectErr) return void (send(FRAME.CONNECT_ERR, b.rawConnectErr), sock.end());
      if (b.connectErr) return void (send(FRAME.CONNECT_ERR, encodeConnectErr(b.connectErr)), sock.end());
      if (b.dataBeforeOk) return void send(FRAME.DATA, enc.encode("early"));
      const ip = isIP(host) ? host : dns.get(host.toLowerCase());
      if (ip === undefined) return void (send(FRAME.CONNECT_ERR, encodeConnectErr("E_DNS")), sock.end());
      if (b.blast !== undefined) {
        connected = true;
        send(FRAME.CONNECT_OK, new Uint8Array(0));
        const chunk = new Uint8Array(TUNNEL.MAX_PAYLOAD).fill(0x61);
        const pump = (): void => {
          while (stats.blastSent < b.blast! && !sock.destroyed) {
            const n = Math.min(chunk.length, b.blast! - stats.blastSent);
            stats.blastSent += n;
            const ok = sock.write(writer!.seal(FRAME.DATA, chunk.subarray(0, n)));
            if (!ok) return void sock.once("drain", pump);
          }
          if (!s2cFin) {
            s2cFin = true;
            send(FRAME.FIN, new Uint8Array(0));
            maybeReceipt();
          }
        };
        pump();
        return;
      }
      const up = tcpConnect({ host: ip, port });
      upstream = up;
      up.on("connect", () => {
        connected = true;
        send(FRAME.CONNECT_OK, new Uint8Array(0));
      });
      up.on("error", () => {
        if (!connected) {
          send(FRAME.CONNECT_ERR, encodeConnectErr("E_CONNECT_FAILED"));
          sock.end();
        } else sock.destroy();
      });
      up.on("data", (c: Buffer) => sendData(new Uint8Array(c)));
      up.on("end", () => {
        s2cFin = true;
        send(FRAME.FIN, new Uint8Array(0));
        maybeReceipt();
      });
    };
    const onFrames = (chunk: Uint8Array): void => {
      for (const f of reader!.push(chunk)) {
        if (f.type === FRAME.CONNECT) {
          const d = parseConnect(f.payload);
          onConnect(d.host, d.port);
        } else if (f.type === FRAME.DATA) {
          stats.maxC2sPayload = Math.max(stats.maxC2sPayload, f.payload.length);
          upstream?.write(f.payload);
        } else if (f.type === FRAME.FIN) {
          c2sFin = true;
          upstream?.end();
          maybeReceipt();
        }
      }
    };
    const onData = (c: Uint8Array): void => {
      if (b.withholdServerHello) {
        stats.bytesWithoutServerHello += c.length;
        return;
      }
      try {
        if (reader === undefined) {
          const all = new Uint8Array(hello.length + c.length);
          all.set(hello);
          all.set(c, hello.length);
          if (all.length < TUNNEL.HELLO_LEN) {
            hello = all;
            return;
          }
          const clientHello = all.subarray(0, TUNNEL.HELLO_LEN);
          stats.hellos.push(toHex(clientHello));
          let keys: { th: Uint8Array; kC2s: Uint8Array; kS2c: Uint8Array };
          let serverHello: Uint8Array | undefined;
          if (early) {
            const { attNonce, epkC } = parseHello(clientHello);
            keys = deriveTunnel({ dh1: x25519.getSharedSecret(xs, epkC), dh2: x25519.getSharedSecret(early.ess, epkC), attNonce, epkC, epkS: early.epkS, xp, ep });
          } else {
            const acc = tunnelServerAccept({ xs, xp, ep, hello: clientHello });
            keys = acc;
            serverHello = acc.serverHello;
          }
          th = keys.th;
          reader = new TunnelReader(keys.kC2s, keys.th, TUNNEL.DIR_C2S);
          writer = new TunnelWriter(keys.kS2c, keys.th, TUNNEL.DIR_S2C);
          if (serverHello !== undefined) {
            sendServerHello(serverHello, b.dataAfterServerHello ? writer.seal(FRAME.DATA, enc.encode("unsolicited")) : undefined);
          }
          c = all.subarray(TUNNEL.HELLO_LEN);
        }
        onFrames(c);
      } catch {
        sock.destroy();
        upstream?.destroy();
      }
    };
    sock.on("data", (c: Buffer) => onData(new Uint8Array(c)));
    sock.on("close", () => upstream?.destroy());
    if (head.length > 0) onData(head);
  }

  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    root,
    registry,
    composeHash,
    keyHash: kh,
    osHash,
    record,
    behaviour,
    dns,
    stats,
    receipts,
    anchorAll() {
      const first = anchored.reduce((n, a) => n + a.count, 0);
      const count = receipts.length - first;
      if (count < 1) return;
      const leaves = receipts.slice(first).map(vpnReceiptLeaf);
      const anchorId = anchorCounts.get(registry) ?? 0;
      anchorCounts.set(registry, anchorId + 1);
      registry.addAnchor({ id: anchorId, key_hash: kh, root: toHex(merkleRoot(leaves)), first_seq: first, count, at_ms: Date.now() });
      anchored.push({ firstSeq: first, count, anchorId });
    },
    close: () =>
      new Promise<void>((ok) => {
        for (const s of sockets) s.destroy();
        server.closeAllConnections();
        server.close(() => ok());
      }),
  };
}

export interface FakeDestination {
  port: number;
  hits(): number;
  received(): string;
  close(): Promise<void>;
}

/** HTTP/1.1 destination: `200 dest-ok:<path>`, POST echoes the body after the prefix, `Connection: close`. */
export async function startDestination(): Promise<FakeDestination> {
  let hits = 0;
  let received = "";
  const server = createServer((req, res) => {
    hits++;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("latin1");
      received += `${req.method} ${req.url}\n${body}`;
      const out = Buffer.from(`dest-ok:${req.url}` + (req.method === "POST" ? body : ""), "latin1");
      res.writeHead(200, { "content-type": "text/plain", "content-length": out.length, connection: "close" });
      res.end(out);
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  return {
    port: (server.address() as AddressInfo).port,
    hits: () => hits,
    received: () => received,
    close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }),
  };
}
