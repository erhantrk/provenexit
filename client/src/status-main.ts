/** Entry of the status bundle: exports `getStatus`; `node provenexit-status.mjs` prints the JSON. */
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { getStatus } from "./status.js";

export { getStatus };
export type { Status, StatusOptions } from "./status.js";

const self = fileURLToPath(import.meta.url);
let direct = false;
try {
  direct = process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(self);
} catch {
  direct = false;
}
if (direct) {
  getStatus().then((s) => {
    process.stdout.write(JSON.stringify(s, null, 2) + "\n");
    // keep-alive sockets of fetch must not hold the process open
    process.exit(0);
  });
}
