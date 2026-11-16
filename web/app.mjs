/**
 * ClauseVault Hybrid — Browser Workbench Controller (`web/app.mjs`)
 */

import { SAMPLE_CONTRACTS } from "./src/sample_contracts.mjs";
import {
  FirebaseHybridAdapter,
  SessionConfigStore,
  inspectChromePromptApi,
} from "./src/firebase_adapter.mjs";
import { ClauseVaultHybridRouter, RouteTaken } from "./src/hybrid_router.mjs";

const sessionStore = new SessionConfigStore();
const adapter = new FirebaseHybridAdapter();
const router = new ClauseVaultHybridRouter({ adapter });

let activeSchedule = SAMPLE_CONTRACTS[0].structuredSchedule;
let latestAnalysis = null;

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(raw) {
  return String(raw)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function refreshNanoStatusChip() {
  const probe = await inspectChromePromptApi(window);
  const chip = $("nano-probe-chip");
  if (probe.isReadyNow) {
    chip.textContent = `Chrome Nano: ${probe.availability} (${probe.apiSurface})`;
  } else {
    chip.textContent = `Chrome Nano: ${probe.availability}`;
  }
}

function populateContractPresets() {
  const select = $("case-select");
  select.innerHTML = "";
  for (const item of SAMPLE_CONTRACTS) {
    const opt = document.createElement("option");
    opt.value = item.id;
    opt.textContent = item.title;
    select.appendChild(opt);
  }
  loadSelectedPreset(SAMPLE_CONTRACTS[0].id);
}

function loadSelectedPreset(caseId) {
  const found = SAMPLE_CONTRACTS.find((c) => c.id === caseId) || SAMPLE_CONTRACTS[0];
  $("raw-clause-editor").value = found.rawText;
  $("mode-select").value = found.recommendedMode;
  activeSchedule = found.structuredSchedule || null;
}

function applyRuntimeSimulationProfile() {
  const profile = $("runtime-profile").value;
  router.simulateOffline = $("toggle-offline").checked;

  if (profile === "auto_live") {
    router.simulateNanoAvailable = null;
    router.simulateCloudFallback = false;
  } else if (profile === "preview_hybrid_warm") {
    router.simulateNanoAvailable = true;
    router.simulateCloudFallback = true;
  } else if (profile === "preview_nano_cold") {
    router.simulateNanoAvailable = false;
    router.simulateCloudFallback = true;
  }
}

function renderSynthesisHtml(synthesis) {
  const contradictionsHtml =
    synthesis.contradictions.length === 0
      ? `<li>None detected across clauses.</li>`
      : synthesis.contradictions
          .map(
            (c) =>
              `<li><strong>[${escapeHtml(c.code)} · ${escapeHtml(c.severity)}]</strong> ${escapeHtml(c.summary)}</li>`
          )
          .join("");

  const findingsHtml =
    synthesis.clauseFindings.length === 0
      ? `<li>All clause &amp; checksum gates passed cleanly.</li>`
      : synthesis.clauseFindings
          .map(
            (f) =>
              `<li><strong>[${escapeHtml(f.ruleId)} · ${escapeHtml(f.severity)}]</strong> (${escapeHtml(f.clauseRef)}): ${escapeHtml(f.detail)}</li>`
          )
          .join("");

  const redlinesHtml = synthesis.recommendedRedlines
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");

  return `
    <div class="syn-section">
      <h3>Executive Hybrid Summary</h3>
      <p class="syn-summary">${escapeHtml(synthesis.executiveSummary)}</p>
    </div>
    <div class="syn-section">
      <h3>Cross-Clause Contradictions (${synthesis.contradictions.length})</h3>
      <ul class="syn-list">${contradictionsHtml}</ul>
    </div>
    <div class="syn-section">
      <h3>Clause &amp; Pre-Redaction Checksum Findings (${synthesis.clauseFindings.length})</h3>
      <ul class="syn-list">${findingsHtml}</ul>
    </div>
    <div class="syn-section">
      <h3>Actionable Redlines (${synthesis.recommendedRedlines.length})</h3>
      <ul class="syn-list">${redlinesHtml}</ul>
    </div>
  `;
}

function renderAnalysis(result) {
  latestAnalysis = result;
  const masked = $("toggle-masked").checked;
  const displaySynthesis = masked
    ? result.rehydratedMaskedSynthesis
    : result.rehydratedLocalFullSynthesis;

  // Route pill
  const pill = $("route-pill");
  pill.textContent = `ROUTE: ${result.routeTaken}`;
  pill.className =
    result.routeTaken === RouteTaken.ON_DEVICE_NANO
      ? "route-pill route-nano"
      : result.routeTaken === RouteTaken.HYBRID_FALLBACK_CLOUD
      ? "route-pill route-cloud"
      : "route-pill route-local";

  // Telemetry strip
  $("m-route").textContent = result.routeTaken;
  $("m-reason").textContent = result.routingReason;
  $("m-sdk-source").textContent = `${result.effectiveMode} -> ${result.sdkInferenceSource}`;
  $("m-backend").textContent = `${result.executionBackend} (${result.telemetry.elapsedMs} ms)`;
  $("m-tokens").textContent = `${result.telemetry.estimatedPromptTokens} / ${result.telemetry.nanoTokenWindow} tok`;
  $("m-clauses").textContent = `${result.telemetry.clauseCount} clause(s) · ${
    result.telemetry.exceedsNanoWindow ? "Exceeds Nano window" : "Fits Nano window"
  }`;
  $("m-vault").textContent = `${result.privacyBoundaryProof.vaultedEntityCount} Vaulted · 0 Leaked`;
  $("m-egress").textContent = `Cloud Egress: ${result.telemetry.outboundCloudBytes} B sanitized`;
  $("m-exposure").textContent = `$${result.shieldReport.numericExposureUsd}`;
  $("m-risk-tier").textContent = `Risk Level: ${displaySynthesis.overallRiskLevel}`;
  $("m-proof-status").textContent = result.privacyBoundaryProof.egressFirewallPassed
    ? "VERIFIED ZERO-PII"
    : "LOCKED LOCAL";
  $("m-proof-hash").textContent = `sha256:${result.privacyBoundaryProof.sanitizedPayloadSha256.slice(0, 18)}...`;

  // Vault chips
  $("vault-chip-count").textContent = String(result.vaultMetadata.vaultedCount);
  const chipList = $("vault-chip-list");
  chipList.innerHTML = "";
  for (const item of result.vaultMetadata.entries) {
    const span = document.createElement("span");
    span.className = "vault-chip";
    span.textContent = `${item.token} -> ${item.maskedPreview}`;
    chipList.appendChild(span);
  }

  // Sanitized wire + SDK params
  $("sanitized-wire-view").textContent = result.sanitizedPrompt;
  const modelParams = adapter.buildGenerativeModelParams({
    mode: result.effectiveMode,
    structuredJson: true,
  });
  $("sdk-config-view").textContent = JSON.stringify(modelParams, null, 2);

  // Risk badge & Synthesis
  const riskBadge = $("risk-badge");
  const lvl = displaySynthesis.overallRiskLevel;
  riskBadge.textContent = `${lvl} RISK`;
  riskBadge.className = `tag tag-${lvl.toLowerCase()}`;

  $("synthesis-view").innerHTML = renderSynthesisHtml(displaySynthesis);
}

async function runAnalysisNow() {
  applyRuntimeSimulationProfile();
  const rawText = $("raw-clause-editor").value;
  const mode = $("mode-select").value;
  const res = await router.analyzeDocument(
    { rawText, structuredSchedule: activeSchedule },
    { mode, requireStructuredJson: true }
  );
  renderAnalysis(res);
}

function buildMarkdownBrief(res) {
  const syn = res.rehydratedMaskedSynthesis;
  const lines = [
    `# ClauseVault Hybrid — Redline & Privacy Proof Brief`,
    ``,
    `- **Route Taken**: \`${res.routeTaken}\` (\`${res.routingReason}\`)`,
    `- **Firebase AI Logic Mode**: \`${res.effectiveMode}\` -> \`${res.sdkInferenceSource}\``,
    `- **Privacy Boundary Proof**: \`egressFirewallPassed=${res.privacyBoundaryProof.egressFirewallPassed}\`, \`vaultedEntityCount=${res.privacyBoundaryProof.vaultedEntityCount}\`, \`rawPiiBytesSentToCloud=0\``,
    `- **Sanitized Payload SHA-256**: \`${res.privacyBoundaryProof.sanitizedPayloadSha256}\``,
    `- **Verified Schedule Variance**: \`$${res.shieldReport.numericExposureUsd}\``,
    ``,
    `## Executive Summary`,
    syn.executiveSummary,
    ``,
    `## Cross-Clause Contradictions`,
    ...(syn.contradictions.length
      ? syn.contradictions.map((c) => `- **[${c.code} · ${c.severity}]** ${c.summary}`)
      : ["- None"]),
    ``,
    `## Actionable Redlines`,
    ...syn.recommendedRedlines.map((r) => `- ${r}`),
    ``,
  ];
  return lines.join("\n");
}

function downloadBlob(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

window.addEventListener("DOMContentLoaded", async () => {
  populateContractPresets();
  // Default to deterministic preview if no session credentials & Chrome Nano isn't enabled yet,
  // while still probing real Chrome `window.LanguageModel` immediately!
  const probe = await inspectChromePromptApi(window);
  const savedSession = sessionStore.loadConfig();
  if (savedSession) {
    try {
      const info = await adapter.initializeFromSessionConfig(savedSession);
      $("cfg-status-msg").textContent = `Connected to Firebase project "${info.projectId}" (${info.cloudModel}) via sessionStorage.`;
    } catch (err) {
      $("cfg-status-msg").textContent = `Session init error: ${err.message}`;
    }
  } else if (!probe.isReadyNow) {
    $("runtime-profile").value = "preview_hybrid_warm";
  }

  await refreshNanoStatusChip();
  await runAnalysisNow();

  $("case-select").addEventListener("change", async (e) => {
    loadSelectedPreset(e.target.value);
    await runAnalysisNow();
  });

  $("raw-clause-editor").addEventListener("input", () => {
    // Custom edits detach preset milestone numbers so user free-form clauses analyze cleanly
    activeSchedule = null;
  });

  for (const id of ["mode-select", "runtime-profile", "toggle-offline", "toggle-masked"]) {
    $(id).addEventListener("change", runAnalysisNow);
  }
  $("btn-analyze").addEventListener("click", runAnalysisNow);

  $("btn-warmup-nano").addEventListener("click", async () => {
    const res = await adapter.warmUpGeminiNano((pct) => {
      $("nano-probe-chip").textContent = `Downloading Nano: ${Math.round(pct * 100)}%`;
    });
    $("nano-probe-chip").textContent = res.warmed
      ? "Chrome Nano: Warm & Ready (On-Device)"
      : `Chrome Nano: ${res.availability} (enable chrome://flags)`;
    await runAnalysisNow();
  });

  // Session Config Modal handlers
  const modal = $("config-modal");
  $("btn-open-config").addEventListener("click", () => modal.showModal());
  $("btn-close-modal").addEventListener("click", () => modal.close());

  $("cfg-json-paste").addEventListener("input", (ev) => {
    try {
      const parsed = JSON.parse(ev.target.value);
      if (parsed.apiKey) $("cfg-api-key").value = parsed.apiKey;
      if (parsed.projectId) $("cfg-project-id").value = parsed.projectId;
      if (parsed.appId) $("cfg-app-id").value = parsed.appId;
    } catch {
      // Wait until valid JSON is pasted
    }
  });

  $("config-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      const saved = sessionStore.saveConfig({
        apiKey: $("cfg-api-key").value,
        projectId: $("cfg-project-id").value,
        appId: $("cfg-app-id").value,
        appCheckSiteKey: $("cfg-appcheck-key").value,
        cloudModel: $("cfg-cloud-model").value || "gemini-2.5-flash",
      });
      const info = await adapter.initializeFromSessionConfig(saved);
      $("runtime-profile").value = "auto_live";
      $("cfg-status-msg").textContent = `Connected Firebase AI Logic (${info.projectId} -> ${info.cloudModel}) in sessionStorage.`;
      modal.close();
      await runAnalysisNow();
    } catch (err) {
      $("cfg-status-msg").textContent = `Config error: ${err.message}`;
    }
  });

  $("btn-wipe-session").addEventListener("click", async () => {
    sessionStore.clearConfig();
    adapter.ai = null;
    adapter.firebaseApp = null;
    $("cfg-api-key").value = "";
    $("cfg-project-id").value = "";
    $("cfg-app-id").value = "";
    $("cfg-json-paste").value = "";
    $("cfg-status-msg").textContent = "Session credentials wiped from sessionStorage.";
    await runAnalysisNow();
  });

  $("btn-export-md").addEventListener("click", () => {
    if (!latestAnalysis) return;
    downloadBlob("clausevault-redline-brief.md", buildMarkdownBrief(latestAnalysis), "text/markdown");
  });

  $("btn-export-json").addEventListener("click", () => {
    if (!latestAnalysis) return;
    const safeReceipt = {
      generatedAtUtc: new Date().toISOString(),
      routeTaken: latestAnalysis.routeTaken,
      effectiveMode: latestAnalysis.effectiveMode,
      sdkInferenceSource: latestAnalysis.sdkInferenceSource,
      telemetry: latestAnalysis.telemetry,
      privacyBoundaryProof: latestAnalysis.privacyBoundaryProof,
      rehydratedMaskedSynthesis: latestAnalysis.rehydratedMaskedSynthesis,
    };
    downloadBlob("clausevault-privacy-receipt.json", JSON.stringify(safeReceipt, null, 2), "application/json");
  });
});
