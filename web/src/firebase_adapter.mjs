/**
 * ClauseVault Hybrid — Official Firebase AI Logic (`firebase/ai` v12.6.0) & Chrome Prompt API Adapter
 * ===================================================================================================
 * Connects browser runtime directly to:
 *  1. Official Firebase JS SDK CDN (`https://www.gstatic.com/firebasejs/12.6.0/firebase-app.js` & `firebase-ai.js`)
 *     using `initializeApp`, `getAI`, `GoogleAIBackend`, `getGenerativeModel`, `InferenceMode`,
 *     `InferenceSource`, and `Schema` (`mode: 'prefer_on_device' | 'only_on_device' | 'prefer_in_cloud'`).
 *  2. Direct Chrome Built-in AI (`window.LanguageModel` / `self.ai?.languageModel`) availability & param inspector.
 *  3. Session-only credential storage (`sessionStorage` strictly; zero hardcoded keys, zero `localStorage`).
 */

export const FIREBASE_CDN_VERSION = "12.6.0";
export const FIREBASE_CDN_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_CDN_VERSION}`;

export const InferenceMode = Object.freeze({
  PREFER_ON_DEVICE: "prefer_on_device",
  ONLY_ON_DEVICE: "only_on_device",
  PREFER_IN_CLOUD: "prefer_in_cloud",
  ONLY_IN_CLOUD: "only_in_cloud",
});

export const InferenceSource = Object.freeze({
  ON_DEVICE: "on_device",
  IN_CLOUD: "in_cloud",
});

const SESSION_STORAGE_KEY = "clausevault_hybrid_firebase_session_v2";

/**
 * Strictly session-scoped credential store (`sessionStorage` ONLY).
 * Never persists keys to disk (`localStorage` / IndexedDB / cookies forbidden).
 */
export class SessionConfigStore {
  constructor(storage = globalThis.sessionStorage || null) {
    this.storage = storage;
  }

  saveConfig(configObj) {
    if (!configObj || typeof configObj !== "object") {
      throw new TypeError("Firebase session config must be a JSON object");
    }
    const sanitized = {
      apiKey: String(configObj.apiKey || "").trim(),
      projectId: String(configObj.projectId || "").trim(),
      appId: String(configObj.appId || "").trim(),
      authDomain: String(configObj.authDomain || "").trim(),
      appCheckSiteKey: String(configObj.appCheckSiteKey || "").trim(),
      cloudModel: String(configObj.cloudModel || "gemini-2.5-flash").trim(),
    };
    if (!sanitized.apiKey || !sanitized.projectId || !sanitized.appId) {
      throw new Error("Firebase config requires at least apiKey, projectId, and appId.");
    }
    if (this.storage) {
      this.storage.setItem(SESSION_STORAGE_KEY, JSON.stringify(sanitized));
    }
    return sanitized;
  }

  loadConfig() {
    if (!this.storage) return null;
    const raw = this.storage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  clearConfig() {
    if (this.storage) {
      this.storage.removeItem(SESSION_STORAGE_KEY);
    }
    return { cleared: true };
  }
}

/** Build the structured JSON schema specification using Firebase AI Logic `Schema` when available. */
export function buildFirebaseSynthesisSchema(SchemaClass) {
  if (!SchemaClass || typeof SchemaClass.object !== "function") {
    return null;
  }
  return SchemaClass.object({
    properties: {
      overallRiskLevel: SchemaClass.enumString({
        enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      }),
      executiveSummary: SchemaClass.string({
        description: "Concise synthesis referencing only sanitized [VAULT_*] tokens.",
      }),
      contradictions: SchemaClass.array({
        items: SchemaClass.object({
          properties: {
            code: SchemaClass.string({}),
            severity: SchemaClass.enumString({ enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }),
            summary: SchemaClass.string({}),
          },
        }),
      }),
      clauseFindings: SchemaClass.array({
        items: SchemaClass.object({
          properties: {
            ruleId: SchemaClass.string({}),
            severity: SchemaClass.enumString({ enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }),
            clauseRef: SchemaClass.string({}),
            detail: SchemaClass.string({}),
          },
        }),
      }),
      recommendedRedlines: SchemaClass.array({
        items: SchemaClass.string({}),
      }),
    },
  });
}

/** Inspect Chrome Built-in AI (`window.LanguageModel` / `self.ai?.languageModel`) live status. */
export async function inspectChromePromptApi(env = globalThis) {
  const lm = env?.LanguageModel || env?.ai?.languageModel || null;
  if (!lm) {
    return {
      supported: false,
      availability: "unsupported_browser",
      apiSurface: "none",
      params: null,
    };
  }

  const surface = env?.LanguageModel ? "window.LanguageModel" : "self.ai.languageModel";
  let availability = "unknown";
  let params = null;

  try {
    if (typeof lm.availability === "function") {
      availability = await lm.availability();
    } else if (typeof lm.capabilities === "function") {
      const caps = await lm.capabilities();
      availability = caps?.available || "unknown";
      params = {
        defaultTemperature: caps?.defaultTemperature ?? null,
        defaultTopK: caps?.defaultTopK ?? null,
        maxTopK: caps?.maxTopK ?? null,
      };
    }
    if (!params && typeof lm.params === "function") {
      params = await lm.params();
    }
  } catch (err) {
    availability = `error: ${err.message}`;
  }

  return {
    supported: availability === "available" || availability === "readily" || availability === "downloadable" || availability === "after-download",
    isReadyNow: availability === "available" || availability === "readily",
    availability,
    apiSurface: surface,
    params,
  };
}

/**
 * Official Firebase AI Logic Hybrid SDK Adapter (`FirebaseHybridAdapter`).
 * Supports dependency-injected SDK modules for deterministic `node --test` tests
 * and loads `https://www.gstatic.com/firebasejs/12.6.0/*.js` natively in browsers.
 */
export class FirebaseHybridAdapter {
  constructor(options = {}) {
    this.sdkLoader = options.sdkLoader || null;
    this.env = options.env || globalThis;
    this.cloudModel = options.cloudModel || "gemini-2.5-flash";
    this.firebaseApp = null;
    this.ai = null;
    this.sdkModules = null;
    this.promptApiSession = null;
  }

  async _loadFirebaseSdk() {
    if (this.sdkModules) return this.sdkModules;
    if (this.sdkLoader) {
      this.sdkModules = await this.sdkLoader();
      return this.sdkModules;
    }
    const [appMod, appCheckMod, aiMod] = await Promise.all([
      import(`${FIREBASE_CDN_BASE}/firebase-app.js`),
      import(`${FIREBASE_CDN_BASE}/firebase-app-check.js`),
      import(`${FIREBASE_CDN_BASE}/firebase-ai.js`),
    ]);
    this.sdkModules = { appMod, appCheckMod, aiMod };
    return this.sdkModules;
  }

  async initializeFromSessionConfig(sessionConfig) {
    const { appMod, appCheckMod, aiMod } = await this._loadFirebaseSdk();
    const firebaseConfig = {
      apiKey: sessionConfig.apiKey,
      projectId: sessionConfig.projectId,
      appId: sessionConfig.appId,
      ...(sessionConfig.authDomain ? { authDomain: sessionConfig.authDomain } : {}),
    };

    const existingApps = typeof appMod.getApps === "function" ? appMod.getApps() : [];
    const appName = "clausevault-hybrid-session";
    const existing = existingApps.find((a) => a.name === appName);
    if (existing && typeof appMod.deleteApp === "function") {
      await appMod.deleteApp(existing);
    }

    this.firebaseApp = appMod.initializeApp(firebaseConfig, appName);

    if (sessionConfig.appCheckSiteKey && appCheckMod?.initializeAppCheck && appCheckMod?.ReCaptchaEnterpriseProvider) {
      appCheckMod.initializeAppCheck(this.firebaseApp, {
        provider: new appCheckMod.ReCaptchaEnterpriseProvider(sessionConfig.appCheckSiteKey),
        isTokenAutoRefreshEnabled: true,
      });
    }

    this.cloudModel = sessionConfig.cloudModel || this.cloudModel;
    this.ai = aiMod.getAI(this.firebaseApp, {
      backend: new aiMod.GoogleAIBackend(),
    });

    return {
      connected: true,
      sdkVersion: appMod.SDK_VERSION || FIREBASE_CDN_VERSION,
      projectId: sessionConfig.projectId,
      cloudModel: this.cloudModel,
    };
  }

  isFirebaseConnected() {
    return Boolean(this.ai && this.sdkModules?.aiMod);
  }

  /** Trigger user-gesture warm-up / session creation on Chrome Built-in AI Gemini Nano. */
  async warmUpGeminiNano(onDownloadProgress = null) {
    const status = await inspectChromePromptApi(this.env);
    const lm = this.env?.LanguageModel || this.env?.ai?.languageModel;
    if (!lm || typeof lm.create !== "function") {
      return { warmed: false, ...status };
    }
    const session = await lm.create({
      temperature: 0.1,
      topK: 3,
      ...(onDownloadProgress
        ? {
            monitor(m) {
              m.addEventListener("downloadprogress", (ev) => {
                onDownloadProgress(ev.loaded ?? 0);
              });
            },
          }
        : {}),
    });
    this.promptApiSession = session;
    return {
      warmed: true,
      ...status,
      availability: "available",
      isReadyNow: true,
    };
  }

  /** Build the exact `getGenerativeModel(ai, hybridParams)` config object for Firebase AI Logic. */
  buildGenerativeModelParams({ mode = InferenceMode.PREFER_ON_DEVICE, structuredJson = false } = {}) {
    const SchemaClass = this.sdkModules?.aiMod?.Schema || null;
    const responseSchema = structuredJson ? buildFirebaseSynthesisSchema(SchemaClass) : null;

    return {
      mode,
      inCloudParams: {
        model: this.cloudModel,
        generationConfig: {
          temperature: 0.1,
          ...(structuredJson
            ? {
                responseMimeType: "application/json",
                ...(responseSchema ? { responseSchema } : {}),
              }
            : {}),
        },
      },
      onDeviceParams: {
        createOptions: {
          temperature: 0.1,
          topK: 3,
        },
      },
    };
  }

  /**
   * Execute inference via live Firebase AI Logic SDK (`getGenerativeModel`), or direct
   * `window.LanguageModel` Prompt API when running purely on-device without Firebase credentials.
   */
  async generateHybrid(sanitizedPrompt, { mode = InferenceMode.PREFER_ON_DEVICE, structuredJson = false } = {}) {
    if (this.isFirebaseConnected()) {
      const { aiMod } = this.sdkModules;
      const modelParams = this.buildGenerativeModelParams({ mode, structuredJson });
      const generativeModel = aiMod.getGenerativeModel(this.ai, modelParams);
      const result = await generativeModel.generateContent(sanitizedPrompt);
      const rawSource = String(result?.response?.inferenceSource || InferenceSource.IN_CLOUD).toLowerCase();
      return {
        provider: "firebase_ai_logic_sdk",
        inferenceSource: rawSource === InferenceSource.ON_DEVICE ? InferenceSource.ON_DEVICE : InferenceSource.IN_CLOUD,
        text: result.response.text(),
        modelParams,
      };
    }

    // Direct Chrome Built-in AI (`window.LanguageModel`) path when on-device mode is eligible and Firebase Cloud isn't configured
    if (mode !== InferenceMode.ONLY_IN_CLOUD && mode !== InferenceMode.PREFER_IN_CLOUD) {
      const lm = this.env?.LanguageModel || this.env?.ai?.languageModel;
      if (lm && typeof lm.create === "function") {
        const probe = await inspectChromePromptApi(this.env);
        if (probe.isReadyNow) {
          const session = this.promptApiSession || (await lm.create({ temperature: 0.1, topK: 3 }));
          this.promptApiSession = session;
          const text = await session.prompt(sanitizedPrompt);
          return {
            provider: "chrome_builtin_prompt_api",
            inferenceSource: InferenceSource.ON_DEVICE,
            text,
            modelParams: this.buildGenerativeModelParams({ mode, structuredJson }),
          };
        }
      }
    }

    return null;
  }
}
