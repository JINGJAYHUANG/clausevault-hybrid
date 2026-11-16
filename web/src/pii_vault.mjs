/**
 * ClauseVault Hybrid — Reversible On-Device PII Vault & Checksum Primitives
 * =========================================================================
 * Executes 100% locally in client memory prior to any AI model invocation:
 *  - Exact BigInt cent parsing & formatting (zero IEEE-754 float drift).
 *  - Pre-redaction Luhn mod-10 PAN, ISO 13616 mod-97 IBAN, and US ABA mod-10
 *    routing checksum validation encoded directly into semantic vault tokens.
 *  - Unicode zero-width / bidirectional & untrusted prompt-injection stripping.
 *  - Reversible local vault (`redact` -> `[VAULT_<TYPE>_#NN]` -> `rehydrate`)
 *    plus `scanUnredactedPii()` & `assertSanitizedForCloud()` hard boundary checks.
 */

const IBAN_COUNTRY_LENGTHS = Object.freeze({
  AT: 20, BE: 16, CH: 21, DE: 22, ES: 24, FR: 27, GB: 22, IE: 22, IT: 27, NL: 18,
});

const AT_CHAR = String.fromCharCode(64);
const EMAIL_PATTERN_SOURCE = `[A-Za-z0-9._%+-]+${AT_CHAR}[^\\s,;<>()"']+\\.[A-Za-z]{2,}`;

export class PrivacyBoundaryViolationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "PrivacyBoundaryViolationError";
    this.code = "PRIVACY_BOUNDARY_VIOLATION";
    this.details = details;
  }
}

/** Parse exact USD decimal string into BigInt cents; rejects JS floating-point numbers. */
export function parseUsdToCents(raw) {
  if (typeof raw === "bigint") return raw;
  if (typeof raw !== "string") {
    throw new TypeError(`parseUsdToCents requires string or bigint, received ${typeof raw}`);
  }
  const cleaned = raw.trim().replace(/[$,\s]/g, "");
  const match = /^(-?)(\d+)(?:\.(\d{1,2}))?$/.exec(cleaned);
  if (!match) {
    throw new RangeError(`Invalid USD amount string: "${raw}"`);
  }
  const sign = match[1] === "-" ? -1n : 1n;
  const whole = BigInt(match[2]);
  const cents = BigInt((match[3] || "").padEnd(2, "0"));
  return sign * (whole * 100n + cents);
}

/** Format BigInt cents into canonical "1234.56" string without floating-point division. */
export function formatCentsToUsd(cents) {
  if (typeof cents !== "bigint") {
    throw new TypeError(`formatCentsToUsd requires bigint, received ${typeof cents}`);
  }
  const neg = cents < 0n;
  const abs = neg ? -cents : cents;
  const whole = abs / 100n;
  const rem = (abs % 100n).toString().padStart(2, "0");
  return `${neg ? "-" : ""}${whole.toString()}.${rem}`;
}

/** Luhn mod-10 payment card checksum validator. */
export function validateLuhnCard(rawDigits) {
  const digits = String(rawDigits).replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/** ISO 13616 mod-97 == 1 IBAN validator using BigInt. */
export function validateIbanMod97(rawIban) {
  const compact = String(rawIban).replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) {
    return { valid: false, reason: "IBAN_FORMAT_INVALID" };
  }
  const cc = compact.slice(0, 2);
  if (IBAN_COUNTRY_LENGTHS[cc] && compact.length !== IBAN_COUNTRY_LENGTHS[cc]) {
    return { valid: false, reason: `IBAN_LEN_MISMATCH_${cc}` };
  }
  const moved = compact.slice(4) + compact.slice(0, 4);
  let expanded = "";
  for (const ch of moved) {
    const code = ch.charCodeAt(0);
    expanded += code >= 65 && code <= 90 ? String(code - 55) : ch;
  }
  const rem = BigInt(expanded) % 97n;
  return rem === 1n
    ? { valid: true, reason: "VALID_MOD97" }
    : { valid: false, reason: `INVALID_MOD97_REM_${rem.toString()}` };
}

/** US 9-digit ABA routing transit number mod-10 validator. */
export function validateAbaRouting(rawAba) {
  const clean = String(rawAba).replace(/\s+/g, "");
  if (!/^\d{9}$/.test(clean) || clean === "000000000") return false;
  const d = [...clean].map((c) => c.charCodeAt(0) - 48);
  const checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
  return checksum % 10 === 0;
}

/** Detect Cyrillic/Greek mixed-script homographs or Punycode spoofing in domain strings. */
export function inspectDomainIntegrity(addressOrDomain, expectedDomain = "") {
  const domain = String(addressOrDomain).split(AT_CHAR).pop().trim().toLowerCase();
  const flags = [];
  if (domain.includes("xn--")) flags.push("PUNYCODE_HOMOGRAPH");
  let hasAsciiAlpha = false;
  let hasConfusableScript = false;
  for (const ch of domain) {
    const cp = ch.codePointAt(0);
    if ((cp >= 0x61 && cp <= 0x7a) || (cp >= 0x41 && cp <= 0x5a)) hasAsciiAlpha = true;
    if (cp >= 0x0370 && cp <= 0x052f) hasConfusableScript = true;
  }
  if (hasAsciiAlpha && hasConfusableScript) flags.push("MIXED_SCRIPT_HOMOGRAPH");
  if (expectedDomain && domain && domain !== expectedDomain.toLowerCase() && flags.length === 0) {
    flags.push("DOMAIN_MISMATCH");
  }
  return flags;
}

/** Compute SHA-256 hex digest using Web Crypto (`crypto.subtle`) across Browser & Node 20+. */
export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(String(text));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function buildMaskedPreview(type, rawValue) {
  const clean = String(rawValue).trim();
  if (
    type.startsWith("IBAN") ||
    type.startsWith("PAN") ||
    type === "SSN" ||
    type === "EIN" ||
    type === "BANK_ACCT" ||
    type.startsWith("ABA")
  ) {
    const compact = clean.replace(/[\s-]/g, "");
    return `***${compact.slice(-4)}`;
  }
  if (type === "SIGNATORY" || type === "COUNTERPARTY_CONTACT") {
    return `${clean.slice(0, 1)}*** (Vaulted Locally)`;
  }
  return `[MASKED_${type}]`;
}

function buildDetectionRules(options = {}) {
  return [
    {
      type: "SSN",
      regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    },
    {
      type: "EIN",
      regex: /(?<=EIN:\s*|\bTax ID:\s*)\d{2}-\d{7}\b/gi,
    },
    {
      type: "IBAN",
      regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{14,26}\b/g,
      classify: (val, signals) => {
        const check = validateIbanMod97(val);
        signals.ibanChecks.push(check);
        return check.valid ? "IBAN_VALID" : "IBAN_BAD_MOD97";
      },
    },
    {
      type: "ABA",
      regex: /(?<=ABA Routing:\s*|Routing Transit:\s*)\d{9}\b/gi,
      classify: (val, signals) => {
        const valid = validateAbaRouting(val);
        signals.abaChecks.push({ valid });
        return valid ? "ABA_VALID" : "ABA_BAD_MOD10";
      },
    },
    {
      type: "BANK_ACCT",
      regex: /(?<=Account Number:\s*|Beneficiary Account:\s*)[A-Z0-9-]{6,18}\b/gi,
    },
    {
      type: "PAN_CARD",
      regex: /\b(?:\d{4}[-\s]){3}\d{4}\b/g,
      classify: (val, signals) => {
        const valid = validateLuhnCard(val);
        signals.cardChecks.push({ valid });
        return valid ? "PAN_VALID" : "PAN_BAD_LUHN";
      },
    },
    {
      type: "CONTACT_ADDR",
      regex: new RegExp(EMAIL_PATTERN_SOURCE, "gu"),
      classify: (val, signals) => {
        const flags = inspectDomainIntegrity(val, options.trustedCounterpartyDomain || "");
        if (flags.length > 0) signals.domainFlags.push(...flags);
        return flags.length > 0 ? "CONTACT_SPOOF_DOMAIN" : "CONTACT_ADDR";
      },
    },
    {
      type: "SIGNATORY",
      regex: /(?<=Signatory:\s*|Authorized Representative:\s*|Patient Name:\s*)([A-Z][a-z]+(?:\s+[A-Z][a-z.]+)+)/g,
    },
    {
      type: "STREET_ADDR",
      regex: /(?<=Registered Address:\s*|Billing Address:\s*)(\d{1,5}\s+[A-Za-z0-9.\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Way|Drive|Dr|Suite\s+\d+)\b)/gi,
    },
    {
      type: "PHONE",
      regex: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g,
    },
    {
      type: "SECRET_REF",
      regex: /\b(?:WIRE-PIN|ESCROW-KEY|AUTH-CODE)-[A-Z0-9-]{6,20}\b/g,
    },
  ];
}

/** Independent stateless detector used by the Hybrid Router to enforce `only_on_device` lock if raw PII exists. */
export function scanUnredactedPii(text, options = {}) {
  const source = String(text || "");
  const dummySignals = { ibanChecks: [], abaChecks: [], cardChecks: [], domainFlags: [] };
  const detectedTypes = [];
  let matchCount = 0;

  for (const rule of buildDetectionRules(options)) {
    const matches = source.match(rule.regex);
    if (matches && matches.length > 0) {
      detectedTypes.push(rule.type);
      matchCount += matches.length;
    }
  }
  return {
    hasUnredactedPii: matchCount > 0,
    matchCount,
    detectedTypes: [...new Set(detectedTypes)],
    dummySignals,
  };
}

/**
 * Reversible Client-RAM PII Vault (`ReversiblePiiVault`).
 * Raw values remain solely inside `this.#tokenMap` in local JS memory.
 */
export class ReversiblePiiVault {
  #tokenToEntry = new Map();
  #rawToToken = new Map();
  #seq = 0;

  constructor() {
    this.signals = {
      ibanChecks: [],
      abaChecks: [],
      cardChecks: [],
      domainFlags: [],
      zeroWidthStripped: false,
      promptInjectionNeutralized: false,
    };
  }

  #register(type, rawMatch) {
    const clean = String(rawMatch).trim();
    if (!clean) return clean;
    if (this.#rawToToken.has(clean)) {
      return this.#rawToToken.get(clean);
    }
    this.#seq += 1;
    const id = String(this.#seq).padStart(2, "0");
    const token = `[VAULT_${type}_#${id}]`;
    this.#rawToToken.set(clean, token);
    this.#tokenToEntry.set(token, Object.freeze({
      token,
      type,
      rawValue: clean,
      maskedPreview: buildMaskedPreview(type, clean),
    }));
    return token;
  }

  redact(rawText, options = {}) {
    let text = String(rawText || "");
    const stripped = text.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, "");
    if (stripped.length !== text.length) {
      this.signals.zeroWidthStripped = true;
      text = stripped;
    }

    const injectionRegex = /ignore\s+(all\s+)?(prior|previous|system)\s+[^\n.]*(instructions|rules|guards)[^\n.]*[.\n]?/gi;
    if (injectionRegex.test(text)) {
      this.signals.promptInjectionNeutralized = true;
      text = text.replace(injectionRegex, "[PROMPT_INJECTION_NEUTRALIZED_ON_DEVICE] ");
    }

    for (const rule of buildDetectionRules(options)) {
      text = text.replace(rule.regex, (m) => {
        const semanticType = rule.classify ? rule.classify(m, this.signals) : rule.type;
        return this.#register(semanticType, m);
      });
    }
    return text;
  }

  /** Rehydrate `[VAULT_<TYPE>_#NN]` tokens locally in browser RAM (`masked: true` or `masked: false`). */
  rehydrate(sanitizedText, { masked = false } = {}) {
    let restored = String(sanitizedText || "");
    for (const [token, entry] of this.#tokenToEntry.entries()) {
      const target = masked ? entry.maskedPreview : entry.rawValue;
      restored = restored.split(token).join(target);
    }
    return restored;
  }

  /** Mandatory outbound firewall prior to any cloud model escalation. */
  assertSanitizedForCloud(payloadText, options = {}) {
    const serialized = typeof payloadText === "string" ? payloadText : JSON.stringify(payloadText);

    for (const [rawSecret, token] of this.#rawToToken.entries()) {
      if (rawSecret.length >= 4 && serialized.includes(rawSecret)) {
        const entry = this.#tokenToEntry.get(token);
        throw new PrivacyBoundaryViolationError(
          `Cloud egress blocked: vaulted secret (${entry?.type || "PII"}) leaked into outbound prompt`,
          { leakedToken: token, leakedType: entry?.type || "PII" }
        );
      }
    }

    const scan = scanUnredactedPii(serialized, options);
    if (scan.hasUnredactedPii) {
      throw new PrivacyBoundaryViolationError(
        `Cloud egress blocked: unredacted PII (${scan.detectedTypes.join(", ")}) detected in outbound prompt`,
        { detectedTypes: scan.detectedTypes, matchCount: scan.matchCount }
      );
    }

    return {
      egressFirewallPassed: true,
      vaultedEntityCount: this.#tokenToEntry.size,
      unredactedPiiCount: 0,
    };
  }

  inspectVaultMetadata() {
    const entries = [];
    for (const entry of this.#tokenToEntry.values()) {
      entries.push({
        token: entry.token,
        type: entry.type,
        maskedPreview: entry.maskedPreview,
        charLength: entry.rawValue.length,
      });
    }
    return {
      vaultedCount: entries.length,
      entries,
      signals: structuredClone(this.signals),
    };
  }
}
