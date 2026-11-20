import { getJson, rpc } from "./core.js";

const DANGEROUS_EXTENSIONS = {
  permanentDelegate: { level: "danger", points: 40, title: "Permanent delegate", detail: "An authority can move or burn tokens out of any wallet." },
  transferHook: { level: "warn", points: 10, title: "Transfer hook", detail: "Every transfer runs extra program code, which can block selling." },
  nonTransferable: { level: "danger", points: 40, title: "Non-transferable", detail: "Tokens cannot be moved once received." },
  defaultAccountState: { level: "warn", points: 15, title: "Default account state", detail: "New token accounts can start frozen." },
};

/** Fetch everything the checks need. Each source may fail on its own. */
export async function gather(mint) {
  const [account, report, pairs] = await Promise.allSettled([
    rpc("getAccountInfo", [mint, { encoding: "jsonParsed" }]),
    getJson(`https://api.rugcheck.xyz/v1/tokens/${mint}/report`, { retries: 2 }),
    getJson(`https://api.dexscreener.com/tokens/v1/solana/${mint}`, { retries: 2 }),
  ]);
  const parsed = account.status === "fulfilled" ? account.value?.value?.data?.parsed : null;
  if (account.status === "fulfilled" && (!parsed || parsed.type !== "mint")) {
    throw new Error("That address is not a token mint. Paste the token's mint address, not a wallet or pool.");
  }
  const list = pairs.status === "fulfilled" && Array.isArray(pairs.value) ? pairs.value : [];
  const pair = list.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0] || null;
  return {
    mint,
    mintInfo: parsed ? { ...parsed.info, program: account.value.value.data.program } : null,
    report: report.status === "fulfilled" ? report.value : null,
    pair,
    unavailable: [
      account.status !== "fulfilled" && "Solana RPC",
      report.status !== "fulfilled" && "RugCheck",
      pairs.status !== "fulfilled" && "DexScreener",
    ].filter(Boolean),
  };
}

/**
 * Turn the gathered data into a list of findings and a 0-100 risk score.
 * Pure function: no network, so it is easy to test and to reuse.
 */
export function assess({ mint, mintInfo, report, pair, now = Date.now() }) {
  const findings = [];
  const add = (level, points, title, detail) => findings.push({ level, points, title, detail });

  if (report?.rugged) add("danger", 100, "Marked as rugged", "RugCheck has this token flagged as already rugged.");

  // 1. Authorities, read straight from the chain when possible.
  const mintAuthority = mintInfo ? mintInfo.mintAuthority : report?.token?.mintAuthority;
  const freezeAuthority = mintInfo ? mintInfo.freezeAuthority : report?.token?.freezeAuthority;
  if (mintInfo || report?.token) {
    if (mintAuthority) add("danger", 35, "Mint authority is active", `${mintAuthority} can create new tokens and dilute holders.`);
    else add("ok", 0, "Mint authority revoked", "No new tokens can be created.");
    if (freezeAuthority) add("danger", 35, "Freeze authority is active", `${freezeAuthority} can freeze wallets so they cannot sell.`);
    else add("ok", 0, "Freeze authority revoked", "Wallets cannot be frozen.");
  }

  // 2. Token-2022 extensions.
  for (const ext of mintInfo?.extensions || []) {
    const name = ext.extension;
    if (name === "transferFeeConfig") {
      const bps = Number(ext.state?.newerTransferFee?.transferFeeBasisPoints ?? ext.state?.olderTransferFee?.transferFeeBasisPoints ?? 0);
      if (bps > 0) add(bps >= 500 ? "danger" : "warn", bps >= 500 ? 30 : 10, `Transfer tax ${(bps / 100).toFixed(2)}%`, "A fee is taken on every transfer, including sells.");
    } else if (DANGEROUS_EXTENSIONS[name]) {
      if (name === "permanentDelegate" && !ext.state?.delegate) continue;
      if (name === "defaultAccountState" && ext.state?.accountState !== "frozen") continue;
      const d = DANGEROUS_EXTENSIONS[name];
      add(d.level, d.points, d.title, d.detail);
    }
  }

  // 3. Holder concentration, pools excluded.
  if (report?.topHolders?.length) {
    const known = report.knownAccounts || {};
    const isPool = (h) => (known[h.owner] || known[h.address])?.type === "AMM";
    // RugCheck sometimes lists closed accounts with the System Program as owner; skip them.
    const wallets = report.topHolders.filter((h) => !isPool(h) && h.owner !== "11111111111111111111111111111111");
    const top10 = wallets.slice(0, 10).reduce((s, h) => s + (Number(h.pct) || 0), 0);
    const biggest = Number(wallets[0]?.pct) || 0;
    if (top10 > 50) add("danger", 25, `Top 10 wallets hold ${top10.toFixed(1)}%`, "A few wallets can crash the price by selling.");
    else if (top10 > 30) add("warn", 12, `Top 10 wallets hold ${top10.toFixed(1)}%`, "Supply is fairly concentrated.");
    else add("ok", 0, `Top 10 wallets hold ${top10.toFixed(1)}%`, "Supply is spread out.");
    if (biggest > 10) add("danger", 15, `Largest wallet holds ${biggest.toFixed(1)}%`, "One wallet owns a large share of supply.");
    else if (biggest > 5) add("warn", 7, `Largest wallet holds ${biggest.toFixed(1)}%`, "One wallet owns a notable share of supply.");
    const insiders = report.topHolders.filter((h) => h.insider).length;
    if (insiders) add("warn", Math.min(15, insiders * 3), `${insiders} top holders flagged as insiders`, "RugCheck links these wallets to the launch.");
  }

  // 4. Creator still holding.
  const supply = Number(mintInfo?.supply ?? report?.token?.supply) || 0;
  if (report?.creator && supply > 0) {
    // RugCheck's creatorBalance is often 0 even while the creator is a top holder,
    // so also count the creator's own accounts in the holder list (raw amounts, like supply).
    const listed = (report.topHolders || []).filter((h) => h.owner === report.creator);
    const listedRaw = listed.reduce((s, h) => s + (Number(h.amount) || 0), 0);
    const share = Math.max(Number(report.creatorBalance) || 0, listedRaw) / supply * 100;
    if (share > 5) add("warn", 8, `Creator holds ${share.toFixed(1)}%`, "The deployer can still sell a large position.");
    else if (share > 0) add("ok", 0, `Creator holds ${share.toFixed(2)}%`, "The deployer holds a small position.");
    else if (report.topHolders?.length && !listed.length) add("ok", 0, "Creator is not a top holder", "The deployer wallet is not among the largest holders (sold or never bought).");
    else add("ok", 0, "Creator holds 0%", "The deployer wallet holds none of the supply (sold or never bought).");
  }

  // 5. Liquidity and age from the deepest pool.
  const onCurve = pair && pair.liquidity?.usd == null && /^pump/.test(pair.dexId || "");
  if (onCurve) {
    add("warn", 8, "Still on the pump.fun bonding curve", "There is no pool to pull, but the coin is tiny and most never graduate.");
    if (pair.pairCreatedAt && now - pair.pairCreatedAt < 3600_000) add("warn", 5, "Launched under an hour ago", "Very new coins fail most often.");
  } else if (pair) {
    const liq = Number(pair.liquidity?.usd) || 0;
    if (liq < 5000) add("danger", 20, `Liquidity is only $${Math.round(liq).toLocaleString()}`, "Small sells will move the price a lot, and exits may be impossible.");
    else if (liq < 20000) add("warn", 10, `Liquidity is $${Math.round(liq).toLocaleString()}`, "Thin liquidity: expect heavy slippage.");
    else add("ok", 0, `Liquidity is $${Math.round(liq).toLocaleString()}`, `Deepest pool is on ${pair.dexId}.`);
    const ageMs = pair.pairCreatedAt ? now - pair.pairCreatedAt : null;
    if (ageMs !== null && ageMs < 3600_000) add("warn", 5, "Pool is under an hour old", "Very new pools fail most often.");
    const sells = Number(pair.txns?.h24?.sells) || 0;
    const buys = Number(pair.txns?.h24?.buys) || 0;
    if (buys >= 50 && sells === 0) add("danger", 40, "Nobody has sold in 24h", `${buys} buys and 0 sells: a classic honeypot pattern.`);
  } else if (String(mint).endsWith("pump")) {
    add("warn", 8, "No trading pool yet", "Looks like a pump.fun coin still on its bonding curve, or one with no trades.");
  } else {
    add("warn", 15, "No trading pool found", "DexScreener lists no pool for this token, so it may not be sellable.");
  }

  // 6. Anything else RugCheck raises that the checks above do not already cover.
  // Only names the checks above really cover. "Creator history of rugged tokens" is not
  // the creator's balance, so it must not be skipped.
  const covered = /mint authority|freeze authority|top 10|holder concentration|single holder|low liquidity|transfer fee|permanent delegate/i;
  for (const risk of report?.risks || []) {
    if (covered.test(risk.name)) continue;
    const danger = risk.level === "danger";
    add(danger ? "danger" : "warn", danger ? 15 : 5, risk.name + (risk.value ? ` (${risk.value})` : ""), risk.description || "Raised by RugCheck.");
  }
  if (Number(report?.graphInsidersDetected) > 0) {
    add("warn", 5, `Insider network of ${report.graphInsidersDetected} wallets`, "RugCheck found wallets connected by transfers around the launch.");
  }

  const score = Math.min(100, findings.reduce((s, f) => s + f.points, 0));
  const verdict = score >= 60 ? "HIGH RISK" : score >= 25 ? "CAUTION" : "LOW RISK";
  const order = { danger: 0, warn: 1, ok: 2 };
  findings.sort((a, b) => order[a.level] - order[b.level] || b.points - a.points);
  return { score, verdict, findings };
}
