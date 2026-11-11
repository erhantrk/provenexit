import { parse } from "yaml";
import { PlrError } from "../errors.js";
import { isPlainObject } from "../bytes.js";
const IMAGE_RE = /^[a-z0-9./_:-]+@sha256:[0-9a-f]{64}$/;
const bad = (why: string): never => { throw new PlrError("E_COMPOSE_POLICY", why); };
export function checkDstackComposePolicy(appCompose: string): { images: string[] } {
  let c: unknown; try { c = JSON.parse(appCompose); } catch { return bad("app-compose is not JSON"); }
  if (!isPlainObject(c) || c.runner !== "docker-compose" || typeof c.docker_compose_file !== "string") bad("runner");
  let dc: unknown; try { dc = parse((c as { docker_compose_file: string }).docker_compose_file); } catch { return bad("docker_compose_file is not YAML"); }
  if (!isPlainObject(dc) || !isPlainObject(dc.services)) bad("services");
  const images: string[] = [];
  for (const [name, s] of Object.entries((dc as { services: Record<string, unknown> }).services)) {
    if (!isPlainObject(s)) bad(`service ${name}`);
    const svc = s as Record<string, unknown>;
    if (typeof svc.image !== "string" || !IMAGE_RE.test(svc.image)) bad(`service ${name}: image not pinned by digest`);
    if ("build" in svc) bad(`service ${name}: build`);
    if (svc.privileged === true) bad(`service ${name}: privileged`);
    images.push(svc.image as string);
  }
  const exit = (dc as { services: Record<string, Record<string, unknown>> }).services.exit;
  if (!isPlainObject(exit) || !isPlainObject(exit.logging) || (exit.logging as Record<string, unknown>).driver !== "none") bad("exit logging is not disabled");
  return { images };
}
