/**
 * ClauseVault Hybrid — Deterministic Local Clause & Remittance Risk Shield
 * ========================================================================
 * Runs 100% locally (`DETERMINISTIC_LOCAL_SHIELD`) with BigInt cent precision:
 *  1. Detects uncapped indemnification / asymmetric liability cap contradictions.
 *  2. Flags predatory auto-renewal notice windows (< 30 days or > 90 days lock-in).
 *  3. Flags unilateral governing-law / mandatory foreign venue shifts.
 *  4. Audits remittance schedules & PO line arithmetic without float drift,
 *     combining pre-redaction IBAN mod-97 / ABA mod-10 / homograph signals.
 */

import { parseUsdToCents, formatCentsToUsd } from "./pii_vault.mjs";

export const RISK_LEVELS = Object.freeze(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/** Estimate LLM token count conservatively (~4 chars/token + punctuation weighting). */
export function estimateTokenCount(text) {
  const s = String(text || "").trim();
  if (!s) return 0;
  const words = s.split(/\s+/).length;
  const charBased = Math.ceil(s.length / 3.8);
  return Math.max(words, charBased);
}

/** Split contract/financial document text into discrete numbered/titled clauses. */
export function splitIntoClauses(sanitizedText) {
  const rawBlocks = String(sanitizedText || "")
    .split(/\n(?=(?:Section|Clause|Article|Schedule|Addendum|\d+\.)\s)/i)
    .map((b) => b.trim())
    .filter(Boolean);
  if (rawBlocks.length > 0) return rawBlocks;
  return [String(sanitizedText || "").trim()].filter(Boolean);
}

/**
 * Deterministic local pre-check & contract/remittance rule evaluator.
 * Produces structured findings even when completely offline or when Nano is unavailable.
 */
export function runDeterministicLocalShield(sanitizedText, vaultMetadata = {}, structuredSchedule = null) {
  const text = String(sanitizedText || "");
  const clauses = splitIntoClauses(text);
  const clauseFindings = [];
  const contradictions = [];
  const recommendedRedlines = [];
  let totalExposureCents = 0n;

  const signals = vaultMetadata.signals || {};

  // 1. Check liability cap vs uncapped indemnity contradiction across clauses
  const capMatch = /liability\s+shall\s+not\s+exceed\s+\$?([\d,]+(?:\.\d{2})?)/i.exec(text);
  const hasUncappedIndemnity =
    /unlimited\s+indemnif|without\s+regard\s+to\s+any\s+liability\s+cap|supersedes\s+all\s+caps|uncapped\s+consequential\s+damages/i.test(
      text
    );
  const capCents = capMatch ? parseUsdToCents(capMatch[1]) : null;

  if (capCents !== null && hasUncappedIndemnity) {
    contradictions.push({
      code: "CROSS_CLAUSE_CAP_OVERRIDE",
      severity: "CRITICAL",
      summary: `Limitation of Liability sets a $${formatCentsToUsd(capCents)} ceiling, but a later Indemnification/Carve-Out clause silently nullifies the cap ("without regard to any liability cap" / unlimited consequential exposure).`,
    });
    recommendedRedlines.push(
      `Amend Indemnification carve-out to keep aggregate liability subject to a defined super-cap (e.g., 2x contract value = $${formatCentsToUsd(capCents * 2n)}) and exclude indirect/consequential damages.`
    );
  }

  // 2. Predatory auto-renewal & narrow cancellation notice window
  const autoRenewMatch = /automatically\s+renew\s+for\s+successive\s+(\d+)[- ]month\s+terms[\s\S]{0,160}?at\s+least\s+(\d+)\s+days\s+prior/i.exec(
    text
  );
  const feeUpliftMatch = /automatic\s+(\d+)%\s+annual\s+(?:price|fee)\s+(?:uplift|escalator|increase)/i.exec(text);
  if (autoRenewMatch) {
    const termMonths = Number.parseInt(autoRenewMatch[1], 10);
    const noticeDays = Number.parseInt(autoRenewMatch[2], 10);
    if (noticeDays >= 90 || termMonths >= 24 || feeUpliftMatch) {
      const upliftPct = feeUpliftMatch ? Number.parseInt(feeUpliftMatch[1], 10) : 0;
      clauseFindings.push({
        ruleId: "CLAUSE-RENEW-01",
        severity: noticeDays >= 90 || upliftPct >= 10 ? "HIGH" : "MEDIUM",
        clauseRef: "Auto-Renewal & Escalator",
        detail: `Multi-term auto-renewal (${termMonths} months) requires ${noticeDays}-day advance cancellation notice${upliftPct ? ` with mandatory ${upliftPct}% annual uplift` : ""}.`,
      });
      recommendedRedlines.push(
        "Replace evergreen lock-in with mutual opt-in renewal or a standard 30-day notice window, and cap renewal price increases at CPI or 3%."
      );
    }
  }

  // 3. Unilateral IP assignment / Asymmetric termination
  if (/assigns\s+all\s+pre-existing\s+intellectual\s+property|irrevocably\s+transfers\s+background\s+ip/i.test(text)) {
    clauseFindings.push({
      ruleId: "CLAUSE-IP-02",
      severity: "CRITICAL",
      clauseRef: "Intellectual Property Assignment",
      detail: "Clause sweeps Customer/Contractor pre-existing Background IP into irrevocable ownership transfer.",
    });
    recommendedRedlines.push(
      "Carve out Background IP and pre-existing tools; grant only a limited, non-exclusive license strictly to deliverables paid in full."
    );
  }

  // 4. Governing law vs Arbitration seat mismatch
  const govLawMatch = /governed\s+by\s+the\s+laws\s+of\s+(?:the\s+State\s+of\s+)?([A-Za-z\s]+?)(?:,|\.|without)/i.exec(text);
  const venueMatch = /exclusive\s+(?:jurisdiction|arbitration\s+seat)\s+in\s+([A-Za-z\s]+?)(?:,|\.|under)/i.exec(text);
  if (
    govLawMatch &&
    venueMatch &&
    govLawMatch[1].trim().toLowerCase() !== venueMatch[1].trim().toLowerCase() &&
    /cayman|singapore|geneva|london|dubai/i.test(venueMatch[1])
  ) {
    contradictions.push({
      code: "JURISDICTION_FORUM_SPLIT",
      severity: "HIGH",
      summary: `Governing substantive law is ${govLawMatch[1].trim()}, while mandatory dispute venue is split offshore to ${venueMatch[1].trim()}, inflating enforcement cost.`,
    });
    recommendedRedlines.push(
      `Align dispute resolution seat with governing law (${govLawMatch[1].trim()}) and allow remote arbitral proceedings.`
    );
  }

  // 5. Pre-redaction BEC / Wire Integrity & Prompt Injection checks
  const badIban = (signals.ibanChecks || []).some((c) => !c.valid);
  const badAba = (signals.abaChecks || []).some((c) => !c.valid);
  const badCard = (signals.cardChecks || []).some((c) => !c.valid);
  const domainSpoof = (signals.domainFlags || []).length > 0;

  if (badIban || badAba || domainSpoof || badCard) {
    const reasons = [
      ...(signals.domainFlags || []),
      ...(badIban ? ["IBAN_MOD97_CHECKSUM_FAILED"] : []),
      ...(badAba ? ["ABA_MOD10_CHECKSUM_FAILED"] : []),
      ...(badCard ? ["CARD_LUHN_CHECKSUM_FAILED"] : []),
    ];
    clauseFindings.push({
      ruleId: "SHIELD-WIRE-01",
      severity: "CRITICAL",
      clauseRef: "Remittance & Payment Coordinates",
      detail: `On-device pre-redaction checksum shield flagged spoofing/corruption indicators: ${reasons.join(", ")}.`,
    });
    recommendedRedlines.push(
      "Place immediate treasury hold on wire disbursement and verify remittance coordinates via out-of-band phone callback."
    );
  }

  if (signals.promptInjectionNeutralized) {
    clauseFindings.push({
      ruleId: "SHIELD-INJECT-01",
      severity: "HIGH",
      clauseRef: "Document Hygiene",
      detail: "Embedded adversarial prompt-override text was neutralized on-device prior to model inference.",
    });
  }

  // 6. Optional BigInt Cent-Exact Schedule / Milestone Reconciliation
  if (structuredSchedule && Array.isArray(structuredSchedule.milestones)) {
    let sumCents = 0n;
    for (const m of structuredSchedule.milestones) {
      const qty = BigInt(m.units ?? 1);
      const unitCents = parseUsdToCents(m.unitRateUsd);
      const contractedCents = m.contractedRateUsd ? parseUsdToCents(m.contractedRateUsd) : unitCents;
      const billedLineCents = qty * unitCents;
      sumCents += billedLineCents;
      if (unitCents > contractedCents) {
        const diff = (unitCents - contractedCents) * qty;
        totalExposureCents += diff;
        clauseFindings.push({
          ruleId: "MATH-RATE-01",
          severity: "HIGH",
          clauseRef: `Schedule Line (${m.label})`,
          detail: `Billed rate $${formatCentsToUsd(unitCents)} exceeds contracted rate $${formatCentsToUsd(contractedCents)} across ${qty.toString()} units (variance $${formatCentsToUsd(diff)}).`,
        });
      }
    }
    if (structuredSchedule.statedTotalUsd) {
      const statedCents = parseUsdToCents(structuredSchedule.statedTotalUsd);
      if (statedCents > sumCents) {
        const footingGap = statedCents - sumCents;
        totalExposureCents += footingGap;
        contradictions.push({
          code: "SCHEDULE_FOOTING_MISMATCH",
          severity: "HIGH",
          summary: `Stated schedule total ($${formatCentsToUsd(statedCents)}) exceeds exact BigInt sum of milestones ($${formatCentsToUsd(sumCents)}) by $${formatCentsToUsd(footingGap)}.`,
        });
      }
      if (badIban || badAba || domainSpoof) {
        totalExposureCents += statedCents;
      }
    }
  }

  // Determine overall risk level deterministically
  const severities = [
    ...clauseFindings.map((f) => f.severity),
    ...contradictions.map((c) => c.severity),
  ];
  let overallRiskLevel = "LOW";
  if (severities.includes("CRITICAL")) overallRiskLevel = "CRITICAL";
  else if (severities.includes("HIGH")) overallRiskLevel = "HIGH";
  else if (severities.includes("MEDIUM")) overallRiskLevel = "MEDIUM";

  return {
    overallRiskLevel,
    clauseCount: clauses.length,
    contradictions,
    clauseFindings,
    recommendedRedlines,
    numericExposureUsd: formatCentsToUsd(totalExposureCents),
    numericExposureCents: totalExposureCents.toString(),
  };
}

/** Validate structured JSON synthesis returned by Gemini Nano or Gemini 2.5 Flash Cloud fallback. */
export function validateSynthesisSchema(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    return { valid: false, errors: ["Root synthesis output must be a JSON object"] };
  }
  const errors = [];
  if (!RISK_LEVELS.includes(candidate.overallRiskLevel)) {
    errors.push(`overallRiskLevel must be one of ${RISK_LEVELS.join("|")}`);
  }
  if (typeof candidate.executiveSummary !== "string" || candidate.executiveSummary.trim().length < 10) {
    errors.push("executiveSummary must be a non-empty string (>= 10 chars)");
  }
  if (!Array.isArray(candidate.contradictions)) {
    errors.push("contradictions must be an array");
  }
  if (!Array.isArray(candidate.clauseFindings)) {
    errors.push("clauseFindings must be an array");
  }
  if (!Array.isArray(candidate.recommendedRedlines)) {
    errors.push("recommendedRedlines must be an array");
  }
  return { valid: errors.length === 0, errors };
}
