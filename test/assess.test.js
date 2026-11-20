import test from "node:test";
import assert from "node:assert/strict";
import { assess } from "../lib/assess.js";

const holders = (pcts, extra = {}) => pcts.map((pct, i) => ({ owner: "W" + i, address: "A" + i, pct, insider: false, ...extra }));
const safe = () => ({
  mint: "SafeMint11111111111111111111111111111111111",
  mintInfo: { mintAuthority: null, freezeAuthority: null, supply: "1000000", decimals: 6, program: "spl-token" },
  report: { topHolders: holders([2, 2, 1, 1, 1]), knownAccounts: {}, creator: "C", creatorBalance: 0, risks: [], token: {} },
  pair: { dexId: "raydium", liquidity: { usd: 250000 }, pairCreatedAt: Date.now() - 86400_000 * 30, txns: { h24: { buys: 100, sells: 90 } } },
});
const titles = (r) => r.findings.map((f) => f.title).join(" | ");

test("a clean token scores low", () => {
  const r = assess(safe());
  assert.equal(r.score, 0);
  assert.equal(r.verdict, "LOW RISK");
});

test("active mint and freeze authority is high risk", () => {
  const d = safe();
  d.mintInfo.mintAuthority = "Auth";
  d.mintInfo.freezeAuthority = "Auth";
  const r = assess(d);
  assert.equal(r.score, 70);
  assert.equal(r.verdict, "HIGH RISK");
  assert.equal(r.findings[0].level, "danger");
});

test("pools are excluded from holder concentration", () => {
  const d = safe();
  d.report.topHolders = [{ owner: "POOL", address: "PA", pct: 80 }, ...holders([2, 2])];
  d.report.knownAccounts = { POOL: { name: "Raydium Pool", type: "AMM" } };
  assert.equal(assess(d).score, 0);
});

test("concentrated supply and thin liquidity add up", () => {
  const d = safe();
  d.report.topHolders = holders([20, 15, 10, 8]);
  d.pair.liquidity.usd = 3000;
  const r = assess(d);
  assert.equal(r.score, 25 + 15 + 20);
  assert.match(titles(r), /Top 10 wallets hold 53\.0%/);
});

test("token-2022 transfer tax and permanent delegate are caught", () => {
  const d = safe();
  d.mintInfo.extensions = [
    { extension: "transferFeeConfig", state: { newerTransferFee: { transferFeeBasisPoints: 1000 } } },
    { extension: "permanentDelegate", state: { delegate: "Someone" } },
    { extension: "permanentDelegate", state: { delegate: null } },
  ];
  const r = assess(d);
  assert.match(titles(r), /Transfer tax 10\.00%/);
  assert.match(titles(r), /Permanent delegate/);
  assert.equal(r.score, 70);
});

test("buys with zero sells is flagged as a honeypot pattern", () => {
  const d = safe();
  d.pair.txns.h24 = { buys: 400, sells: 0 };
  assert.match(titles(assess(d)), /Nobody has sold/);
});

test("a pump.fun mint with no pool is a warning, not a failure", () => {
  const d = safe();
  d.mint = "AF4R5UZVcnghCSko7Y2P1UNKNVxQCL6q1Jvs5fnppump";
  d.pair = null;
  const r = assess(d);
  assert.equal(r.score, 8);
});

test("rugged flag maxes the score, and extra RugCheck risks are included once", () => {
  const d = safe();
  d.report.rugged = true;
  d.report.risks = [{ name: "Mutable metadata", level: "warn", description: "x" }, { name: "Low Liquidity", level: "danger" }];
  const r = assess(d);
  assert.equal(r.score, 100);
  assert.match(titles(r), /Mutable metadata/);
  assert.doesNotMatch(titles(r), /Low Liquidity/);
});

test("works from the RugCheck report alone when the RPC is down", () => {
  const d = safe();
  d.mintInfo = null;
  d.report.token = { mintAuthority: "Auth", freezeAuthority: null, supply: 1000 };
  assert.equal(assess(d).score, 35);
});

test("a coin on the pump.fun bonding curve is not treated as zero liquidity", () => {
  const d = safe();
  d.pair = { dexId: "pumpfun", pairCreatedAt: Date.now() - 120_000, txns: { h24: { buys: 3, sells: 1 } } };
  const r = assess(d);
  assert.equal(r.score, 13);
  assert.match(titles(r), /bonding curve/);
});

test("RugCheck's creator rug history is reported, and its holder concentration risk is not counted twice", () => {
  const d = safe();
  d.report.risks = [
    { name: "Creator history of rugged tokens", value: "", description: "Creator has a history of rugging tokens.", level: "danger" },
    { name: "High holder concentration", value: "", description: "The top 10 users hold more than 50% token supply", level: "warn" },
  ];
  const r = assess(d);
  assert.match(titles(r), /Creator history of rugged tokens/);
  assert.doesNotMatch(titles(r), /High holder concentration/);
  assert.equal(r.score, 15);
});
