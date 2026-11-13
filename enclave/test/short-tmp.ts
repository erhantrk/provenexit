// Unix socket paths are limited to 104 bytes on macOS (108 on Linux). The tests start mock TDX hosts whose sockets
// live under their temp dir, so a temp dir inside a deep clone (e.g. /Users/<name>/some/long/folder/provenexit/enclave)
// overflows the limit and the host refuses with E_SOCKET_PATH. Test temp dirs therefore go under /tmp, whatever the
// clone path. (os.tmpdir() is no help: on macOS it is a long /var/folders/... path.)
import { mkdtempSync, realpathSync } from "node:fs";
import { join } from "node:path";

export function shortTmp(prefix: string): string {
  // realpath: on macOS /tmp is a symlink to /private/tmp, and the launched exit's Node permission allow-list must name
  // the real path.
  return realpathSync(mkdtempSync(join("/tmp", `plr-${prefix}`)));
}
