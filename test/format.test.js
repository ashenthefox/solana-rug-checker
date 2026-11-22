import test from "node:test";
import assert from "node:assert/strict";
import { marketLine } from "../lib/format.js";
const base = ["$0.01", "mcap $1.00M", "liquidity bonding curve", "24h volume $100.0K", "age 30d"];
test("missing holder count has no dangling separator", () => {
  const line = marketLine([...base, ""]);
  assert.equal(line, base.join("  ·  "));
  assert.doesNotMatch(line, /[·\s]$/);
});
test("known holder count is appended", () => assert.equal(marketLine([...base, "1,234 holders"]), base.join("  ·  ") + "  ·  1,234 holders"));
test("zero holders is not omitted", () => assert.equal(marketLine([...base, "0 holders"]), base.join("  ·  ") + "  ·  0 holders"));
test("empty optional entries are omitted", () => assert.equal(marketLine(["price", "", "age 1d", null, undefined]), "price  ·  age 1d"));
test("no entries produces empty string", () => assert.equal(marketLine([]), ""));
