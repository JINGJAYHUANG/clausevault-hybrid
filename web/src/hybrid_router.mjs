/**
 * ClauseVault Hybrid — Policy-Driven Hybrid AI Router & Telemetry Engine
 * ======================================================================
 * Enforces strict privacy & routing invariants across three execution routes:
 *   - `ON_DEVICE_NANO`            (Gemini Nano via Firebase `prefer_on_device`/`only_on_device` or Chrome `LanguageModel`)
 *   - `HYBRID_FALLBACK_CLOUD`     (Sanitized-only escalation via Firebase AI Logic -> Gemini 2.5 Flash)
 *   - `DETERMINISTIC_LOCAL_SHIELD` (Zero-LLM cent-exact & rule shield when offline / Nano unavailable under strict local lock)
 *
 * Hard Invariant:
 *   If ANY unredacted PII is present in the candidate prompt (`scanUnredactedPii().hasUnredactedPii`),
 *   routing locks to `only_on_device` and throws `PrivacyBoundaryViolationError` before ANY cloud call.
 */

import {
  ReversiblePiiVault,
  PrivacyBoundaryViolationError,
  scanUnredactedPii,
  sha256Hex,
} from "./pii_vault.mjs";
import {
  estimateTokenCount,
  splitIntoClauses,
  runDeterministicLocalShield,
  validateSynthesisSchema,
} from "./clause_shield.mjs";
import {
  FirebaseHybridAdapter,
  InferenceMode,
  InferenceSource,
  inspectChromePromptApi,
} from "./firebase_adapter.mjs";

export const RouteTaken = Object.freeze({
  ON_DEVICE_NANO: "ON_DEVICE_NANO",
  HYBRID_FALLBACK_CLOUD: "HYBRID_FALLBACK_CLOUD",
  DETERMINISTIC_LOCAL_SHIELD: "DETERMINISTIC_LOCAL_SHIELD",
});

export class ClauseVaultHybridRouter {
  constructor(options = {}) {
    this.nanoTokenWindow = options.nanoTokenWindow ?? 320;
    this.complexClauseThreshold = options.complexClauseThreshold ?? 4;
    this.adapter = options.adapter || new FirebaseHybridAdapter(options);
    // Optional simulation flags for deterministic testing & zero-key judge demo preview
    this.simulateNanoAvailable = options.simulateNanoAvailable ?? null;
    this.simulateCloudFallback = options.simulateCloudFallback ?? false;
    this.simulateOffline = options.simulateOffline ?? false;
  }

  /**
   * Pure routing policy calculator — directly unit-tested in `tests/hybrid_router.test.mjs`.
   */
  decideRoute({
    requestedMode = InferenceMode.PREFER_ON_DEVICE,
    hasUnredactedPii = false,
    estimatedTokens = 0,
    clauseCount = 1,
    requireStructuredJson = false,
    nanoReady = false,
    isOffline = false,
  }) {
    // HARD INVARIANT 1: Unredacted PII detected -> hard lock to ONLY_ON_DEVICE, forbid all cloud paths!
    if (hasUnredactedPii) {
      if (requestedMode === InferenceMode.PREFER_IN_CLOUD || requestedMode === InferenceMode.ONLY_IN_CLOUD) {
        throw new PrivacyBoundaryViolationError(
          `Requested cloud mode "${requestedMode}" rejected: unredacted PII detected; router hard-locked to only_on_device.`,
          { requestedMode, enforcedMode: InferenceMode.ONLY_ON_DEVICE }
        );
      }
      if (!nanoReady) {
        return {
          effectiveMode: InferenceMode.ONLY_ON_DEVICE,
          targetRoute: RouteTaken.DETERMINISTIC_LOCAL_SHIELD,
          reason: "UNREDACTED_PII_HARD_LOCK_LOCAL_SHIELD",
          exceedsNanoWindow: estimatedTokens > this.nanoTokenWindow,
        };
      }
      return {
        effectiveMode: InferenceMode.ONLY_ON_DEVICE,
        targetRoute: RouteTaken.ON_DEVICE_NANO,
        reason: "UNREDACTED_PII_HARD_LOCK_ON_DEVICE_NANO",
        exceedsNanoWindow: estimatedTokens > this.nanoTokenWindow,
      };
    }

    const exceedsNanoWindow = estimatedTokens > this.nanoTokenWindow;
    const needsComplexCloudSchema =
      requireStructuredJson && (exceedsNanoWindow || clauseCount >= this.complexClauseThreshold);

    // Explicit ONLY_ON_DEVICE mode
    if (requestedMode === InferenceMode.ONLY_ON_DEVICE) {
      return nanoReady
        ? {
            effectiveMode: InferenceMode.ONLY_ON_DEVICE,
            targetRoute: RouteTaken.ON_DEVICE_NANO,
            reason: "EXPLICIT_ONLY_ON_DEVICE_NANO",
            exceedsNanoWindow,
          }
        : {
            effectiveMode: InferenceMode.ONLY_ON_DEVICE,
            targetRoute: RouteTaken.DETERMINISTIC_LOCAL_SHIELD,
            reason: "ONLY_ON_DEVICE_NANO_UNAVAILABLE_SHIELD_FALLBACK",
            exceedsNanoWindow,
          };
    }

    // Offline handling
    if (isOffline) {
      if (requestedMode === InferenceMode.ONLY_IN_CLOUD) {
        throw new Error("InferenceMode.ONLY_IN_CLOUD failed: device is currently offline.");
      }
      return nanoReady
        ? {
            effectiveMode: InferenceMode.ONLY_ON_DEVICE,
            targetRoute: RouteTaken.ON_DEVICE_NANO,
            reason: "OFFLINE_FALLBACK_TO_ON_DEVICE_NANO",
            exceedsNanoWindow,
          }
        : {
            effectiveMode: InferenceMode.ONLY_ON_DEVICE,
            targetRoute: RouteTaken.DETERMINISTIC_LOCAL_SHIELD,
            reason: "OFFLINE_DETERMINISTIC_LOCAL_SHIELD",
            exceedsNanoWindow,
          };
    }

    // Explicit Cloud preference (`prefer_in_cloud` / `only_in_cloud`) on sanitized text
    if (requestedMode === InferenceMode.PREFER_IN_CLOUD || requestedMode === InferenceMode.ONLY_IN_CLOUD) {
      return {
        effectiveMode: requestedMode,
        targetRoute: RouteTaken.HYBRID_FALLBACK_CLOUD,
        reason: "SANITIZED_EXPLICIT_CLOUD_PREFERENCE",
        exceedsNanoWindow,
      };
    }

    // Default `prefer_on_device` hybrid policy
    if (needsComplexCloudSchema) {
      return {
        effectiveMode: InferenceMode.PREFER_IN_CLOUD,
        targetRoute: RouteTaken.HYBRID_FALLBACK_CLOUD,
        reason: exceedsNanoWindow
          ? "SANITIZED_TOKEN_WINDOW_ESCALATION_TO_CLOUD"
          : "SANITIZED_CROSS_CLAUSE_SCHEMA_ESCALATION_TO_CLOUD",
        exceedsNanoWindow,
      };
    }

    if (nanoReady && !exceedsNanoWindow) {
      return {
        effectiveMode: InferenceMode.PREFER_ON_DEVICE,
        targetRoute: RouteTaken.ON_DEVICE_NANO,
        reason: "SANITIZED_WITHIN_NANO_WINDOW_ON_DEVICE",
        exceedsNanoWindow: false,
      };
    }

    return {
      effectiveMode: InferenceMode.PREFER_ON_DEVICE,
      targetRoute: RouteTaken.HYBRID_FALLBACK_CLOUD,
      reason: exceedsNanoWindow
        ? "SANITIZED_EXCEEDS_NANO_WINDOW_CLOUD_FALLBACK"
        : "NANO_UNAVAILABLE_FIREBASE_CLOUD_FALLBACK",
      exceedsNanoWindow,
    };
  }

  buildSanitizedPrompt(sanitizedText, shieldReport, { structuredJson = true } = {}) {
    const header = [
      "You are ClauseVault Hybrid Risk Analyst.",
      "Analyze the PII-sanitized contract/financial clauses and deterministic pre-check signals below.",
      "Preserve vault placeholders such as [VAULT_SSN_#01] or [VAULT_IBAN_VALID_#02] verbatim for client-side rehydration.",
      structuredJson
        ? "Return valid JSON with keys: overallRiskLevel, executiveSummary, contradictions, clauseFindings, recommendedRedlines."
        : "Provide a concise risk summary and concrete redline guidance.",
      "--- SANITIZED CLAUSES ---",
      sanitizedText,
      "--- DETERMINISTIC SHIELD SIGNALS ---",
      JSON.stringify({
        overallRiskLevel: shieldReport.overallRiskLevel,
        contradictions: shieldReport.contradictions,
        clauseFindings: shieldReport.clauseFindings,
        numericExposureUsd: shieldReport.numericExposureUsd,
      }),
    ];
    return header.join("\n");
  }

  _buildSynthesisFromShield(shieldReport, vaultMeta, routeTaken, reason) {
    const leadToken = vaultMeta.entries[0]?.token || "[LOCAL_DOCUMENT]";
    const findingCount = shieldReport.clauseFindings.length + shieldReport.contradictions.length;
    const executiveSummary =
      findingCount === 0
        ? `Route ${routeTaken} (${reason}): ${leadToken} passed all ${shieldReport.clauseCount} clause and remittance checks with $0.00 variance and zero high-risk contradictions.`
        : `Route ${routeTaken} (${reason}): ${leadToken} flagged ${shieldReport.contradictions.length} cross-clause contradiction(s) and ${shieldReport.clauseFindings.length} risk item(s) across ${shieldReport.clauseCount} clauses (verified exposure: $${shieldReport.numericExposureUsd}).`;

    return {
      overallRiskLevel: shieldReport.overallRiskLevel,
      executiveSummary,
      contradictions: shieldReport.contradictions,
      clauseFindings: shieldReport.clauseFindings,
      recommendedRedlines:
        shieldReport.recommendedRedlines.length > 0
          ? shieldReport.recommendedRedlines
          : ["No redlines required; retain standard mutual audit trail."],
    };
  }

  /**
   * Execute full Hybrid AI analysis:
   *   1. Tokenize PII on-device into `ReversiblePiiVault` (unless `skipRedactionForPolicyTest` is set in security tests).
   *   2. Run `DETERMINISTIC_LOCAL_SHIELD` cent-exact & cross-clause pre-check.
   *   3. Compute hybrid route (`ON_DEVICE_NANO`, `HYBRID_FALLBACK_CLOUD`, or `DETERMINISTIC_LOCAL_SHIELD`).
   *   4. Enforce `vault.assertSanitizedForCloud()` before any cloud egress, call Firebase AI Logic / Nano,
   *      validate structured JSON schema, and rehydrate vault tokens strictly in local memory.
   */
  async analyzeDocument(docInput, options = {}) {
    const startPerf = performance.now();
    const rawText = typeof docInput === "string" ? docInput : docInput.rawText;
    const structuredSchedule = typeof docInput === "object" ? docInput.structuredSchedule || null : null;
    const trustedCounterpartyDomain =
      typeof docInput === "object" ? docInput.trustedCounterpartyDomain || "" : "";

    const requestedMode = options.mode || InferenceMode.PREFER_ON_DEVICE;
    const requireStructuredJson = options.requireStructuredJson ?? true;
    const skipRedactionForPolicyTest = options.skipRedactionForPolicyTest === true;

    const vault = new ReversiblePiiVault();
    const candidateText = skipRedactionForPolicyTest
      ? String(rawText || "")
      : vault.redact(rawText, { trustedCounterpartyDomain });
    const vaultMeta = vault.inspectVaultMetadata();

    const shieldReport = runDeterministicLocalShield(candidateText, vaultMeta, structuredSchedule);
    const clauses = splitIntoClauses(candidateText);
    const candidatePrompt = this.buildSanitizedPrompt(candidateText, shieldReport, {
      structuredJson: requireStructuredJson,
    });

    const piiScan = scanUnredactedPii(candidatePrompt, { trustedCounterpartyDomain });
    const estimatedTokens = estimateTokenCount(candidatePrompt);

    let nanoProbe = { isReadyNow: false, availability: "simulated", apiSurface: "simulated" };
    if (this.simulateNanoAvailable !== null) {
      nanoProbe = {
        supported: Boolean(this.simulateNanoAvailable),
        isReadyNow: Boolean(this.simulateNanoAvailable),
        availability: this.simulateNanoAvailable ? "available" : "unavailable",
        apiSurface: "simulated_nano_probe",
      };
    } else {
      nanoProbe = await inspectChromePromptApi(this.adapter.env);
    }

    const isOffline =
      this.simulateOffline ||
      (typeof navigator !== "undefined" && navigator.onLine === false);

    const decision = this.decideRoute({
      requestedMode,
      hasUnredactedPii: piiScan.hasUnredactedPii,
      estimatedTokens,
      clauseCount: clauses.length,
      requireStructuredJson,
      nanoReady: nanoProbe.isReadyNow,
      isOffline,
    });

    let routeTaken = decision.targetRoute;
    let executionBackend = "deterministic_local_engine";
    let sdkInferenceSource = InferenceSource.ON_DEVICE;
    let egressFirewall = {
      egressFirewallPassed: !piiScan.hasUnredactedPii,
      vaultedEntityCount: vaultMeta.vaultedCount,
      unredactedPiiCount: piiScan.matchCount,
    };
    let outboundCloudBytes = 0;
    let synthesisObject = null;

    if (routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD) {
      // Mandatory hard firewall check before ANY cloud call!
      egressFirewall = vault.assertSanitizedForCloud(candidatePrompt, { trustedCounterpartyDomain });
    }

    // Attempt live Firebase AI Logic SDK or Chrome Prompt API execution if available
    if (routeTaken !== RouteTaken.DETERMINISTIC_LOCAL_SHIELD) {
      const canCallLiveCloud =
        routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD && this.adapter.isFirebaseConnected();
      const canCallLiveOnDevice =
        routeTaken === RouteTaken.ON_DEVICE_NANO &&
        (this.adapter.isFirebaseConnected() || this.simulateNanoAvailable === null);

      if (canCallLiveCloud || canCallLiveOnDevice) {
        const liveRes = await this.adapter.generateHybrid(candidatePrompt, {
          mode: decision.effectiveMode,
          structuredJson: requireStructuredJson,
        });
        if (liveRes) {
          executionBackend = liveRes.provider;
          sdkInferenceSource = liveRes.inferenceSource;
          routeTaken =
            sdkInferenceSource === InferenceSource.IN_CLOUD
              ? RouteTaken.HYBRID_FALLBACK_CLOUD
              : RouteTaken.ON_DEVICE_NANO;

          if (routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD) {
            egressFirewall = vault.assertSanitizedForCloud(candidatePrompt, { trustedCounterpartyDomain });
            outboundCloudBytes = new TextEncoder().encode(candidatePrompt).length;
          }

          try {
            const cleanedJson = liveRes.text.replace(/^```json\s*|\s*```$/gi, "").trim();
            const parsed = JSON.parse(cleanedJson);
            const check = validateSynthesisSchema(parsed);
            if (check.valid) {
              synthesisObject = parsed;
            }
          } catch {
            synthesisObject = {
              ...this._buildSynthesisFromShield(shieldReport, vaultMeta, routeTaken, decision.reason),
              executiveSummary: liveRes.text.trim(),
            };
          }
        }
      }

      // Deterministic Synthetic / Preview Adapter when live cloud credentials or Chrome Nano flags aren't active yet
      if (!synthesisObject) {
        if (routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD && !this.simulateCloudFallback && !this.adapter.isFirebaseConnected()) {
          // Without user-supplied Firebase Cloud credentials in sessionStorage, never fake a live cloud call:
          // unless `simulateCloudFallback` preview toggle is enabled, degrade transparently to DETERMINISTIC_LOCAL_SHIELD!
          routeTaken = RouteTaken.DETERMINISTIC_LOCAL_SHIELD;
          sdkInferenceSource = InferenceSource.ON_DEVICE;
          executionBackend = "deterministic_local_shield_no_cloud_key";
        } else {
          sdkInferenceSource =
            routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD
              ? InferenceSource.IN_CLOUD
              : InferenceSource.ON_DEVICE;
          executionBackend =
            routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD
              ? "simulated_hybrid_cloud_preview"
              : "simulated_on_device_nano_preview";
          if (routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD) {
            outboundCloudBytes = new TextEncoder().encode(candidatePrompt).length;
          }
        }
        synthesisObject = this._buildSynthesisFromShield(
          shieldReport,
          vaultMeta,
          routeTaken,
          decision.reason
        );
      }
    } else {
      synthesisObject = this._buildSynthesisFromShield(
        shieldReport,
        vaultMeta,
        RouteTaken.DETERMINISTIC_LOCAL_SHIELD,
        decision.reason
      );
    }

    const schemaValidation = validateSynthesisSchema(synthesisObject);
    const sanitizedJsonStr = JSON.stringify(synthesisObject, null, 2);
    const rehydratedMaskedJson = JSON.parse(vault.rehydrate(sanitizedJsonStr, { masked: true }));
    const rehydratedLocalFullJson = JSON.parse(vault.rehydrate(sanitizedJsonStr, { masked: false }));

    const [rawDocSha256, sanitizedPromptSha256] = await Promise.all([
      sha256Hex(rawText),
      sha256Hex(candidatePrompt),
    ]);

    const elapsedMs = Math.max(1, Math.round((performance.now() - startPerf) * 100) / 100);

    return {
      routeTaken,
      requestedMode,
      effectiveMode: decision.effectiveMode,
      routingReason: decision.reason,
      sdkInferenceSource,
      executionBackend,
      cloudModelTarget:
        routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD ? this.adapter.cloudModel : null,
      telemetry: {
        estimatedPromptTokens: estimatedTokens,
        nanoTokenWindow: this.nanoTokenWindow,
        exceedsNanoWindow: decision.exceedsNanoWindow,
        clauseCount: clauses.length,
        outboundCloudBytes,
        elapsedMs,
        chromePromptApi: nanoProbe,
        firebaseConnected: this.adapter.isFirebaseConnected(),
      },
      privacyBoundaryProof: {
        rawDocumentSha256: rawDocSha256,
        sanitizedPayloadSha256: sanitizedPromptSha256,
        hashesDistinctWhenPiiPresent: vaultMeta.vaultedCount > 0 ? rawDocSha256 !== sanitizedPromptSha256 : true,
        unredactedPiiDetected: piiScan.hasUnredactedPii,
        vaultedEntityCount: vaultMeta.vaultedCount,
        egressFirewallPassed: egressFirewall.egressFirewallPassed,
        rawPiiBytesSentToCloud: 0,
      },
      vaultMetadata: vaultMeta,
      shieldReport,
      schemaValidation,
      sanitizedText: candidateText,
      sanitizedPrompt: candidatePrompt,
      sanitizedSynthesis: synthesisObject,
      rehydratedMaskedSynthesis: rehydratedMaskedJson,
      rehydratedLocalFullSynthesis: rehydratedLocalFullJson,
    };
  }
}
