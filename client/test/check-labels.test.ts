// The client's own wording for a check, where it differs from the shared `CHECKS` name.
import { describe, expect, it } from "vitest";
import { CHECKS } from "@plr/shared";
import { checkLines } from "../src/verify-report.js";

describe("check labels", () => {
  it("the key-binding check is named after the exit, in every list the client prints or returns", () => {
    for (const o of [{}, { intel: true }, { intel: true, codeHash: "verified" as const }]) {
      const names = checkLines(undefined, undefined, o).map((l) => l.name);
      expect(names).toContain("report_data binds the exit's keys");
      expect(names).not.toContain(CHECKS.REPORT_DATA_KEYS);
    }
  });
});
