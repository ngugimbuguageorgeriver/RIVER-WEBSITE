// RIVER WEBSITE/backend/authorization/policy/opaWasm.runtime.ts


/**
 *
 * WASM runtime initialization example for OPA policies, with HTTP OPA fallback.
 *
 * Two modes: This file provides a practical WASM initialization example and fallback to HTTP OPA evaluation. 
 * In production you will either: 
 *                 (A) run OPA as a sidecar/central service (HTTP) or 
 *                 (B) load compiled Rego → 
 *                                    WASM and evaluate locally. I include complete code for both paths.
 *             - HTTP OPA: call a central OPA server via REST (fast to iterate)
 *             - WASM: load compiled Rego->WASM policy bundle and evaluate locally (low-latency, no network)
 *
 * Installation notes:
 *  - If you plan to use WASM: install an OPA wasm helper. Two common approaches:
 *      1) Use the official OPA wasm-loader approach (native WebAssembly instantiation).
 *      2) Use community SDKs such as '@open-policy-agent/opa-wasm' if available.
 *
 * The code below implements an HTTP OPA eval path and a WASM loader placeholder using
 *             WebAssembly.instantiateStreaming / instantiate. The WASM evaluation code is intentionally
 *                      explicit so you can adapt to your preferred wasm loader library.
 *
 * Environment variables:
 *  - OPA_URL : if set, HTTP evaluation will be used (e.g. http://localhost:8181/v1/data/authz/allow)
 *  - OPA_WASM_PATH : path to compiled wasm policy file (e.g. ./policies/authz.wasm)
 */

import fs from "fs";
import path from "path";
import fetch from "node-fetch";

const OPA_URL = process.env.OPA_URL || ""; // if present, use HTTP OPA
const OPA_EVAL_TIMEOUT = parseInt(process.env.OPA_EVAL_TIMEOUT || "5000", 10);

// ----- HTTP OPA evaluation (simple, recommended for early stages) -----
export async function evaluatePolicyHttp(input: any): Promise<{ allow: boolean; details?: any }> {
  if (!OPA_URL) return { allow: false, details: "OPA_URL not configured" };

  const res = await fetch(OPA_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input }),
    timeout: OPA_EVAL_TIMEOUT,
  });

  if (!res.ok) {
    return { allow: false, details: { status: res.status, text: await res.text() } };
  }
  const json = await res.json();
  return { allow: !!json.result, details: json };
}

// ----- WASM runtime loader & evaluator -----
// The WASM evaluator below uses the standard WebAssembly API. OPA emits a WASM module
//      that expects a standard runtime environment. For production usage, you should use the
//           official OPA wasm helper (or the compiled SDK) that sets up the runtime memory, data and
//                  convenience functions. The code below demonstrates the general steps and provides placeholders.

/**
 * WASM runtime holder
 */
let wasmInstance: WebAssembly.Instance | null = null;
let wasmMemory: WebAssembly.Memory | null = null;
let opaExports: any = null;

/**
 * Load a compiled OPA wasm policy from disk and instantiate it.
 * @param wasmFilePath relative or absolute path to compiled policy.wasm
 */
export async function loadWasmPolicy(wasmFilePath: string) {
  if (!fs.existsSync(wasmFilePath)) throw new Error(`WASM file not found: ${wasmFilePath}`);

  // Read wasm bytes
  const wasmBytes = fs.readFileSync(wasmFilePath);

  // Create memory for the module; OPA wasm policies expect a memory export.
  wasmMemory = new WebAssembly.Memory({ initial: 256, maximum: 4096 });

  // Minimalistic imports for many wasm modules (extend as OPA requires)
  const imports = {
    env: {
      memory: wasmMemory,
      // Add other env functions if the module requires them.
      // For example, OPA SDK expects functions and handles for host calls for printing / syscalls.
      // If your wasm fails to instantiate, use an OPA wasm SDK loader instead which wires these for you.
    },
  };

  const { instance } = await WebAssembly.instantiate(wasmBytes, imports);

  wasmInstance = instance;
  opaExports = (instance.exports as any);

  // Example: some OPA wasm modules expose `opa_heap_ptr_get` / `opa_malloc` / `opa_eval` exports.
  // You will need to inspect the wasm exports (console.log(Object.keys(opaExports))) and call the right functions.
  console.log("WASM policy loaded. Exports:", Object.keys(opaExports));
}

/**
 * Evaluate input using the loaded WASM policy.
 * NOTE: This is a generic wrapper. OPA WASM expects specific memory layout and ABI operations.
 * For production: replace this with the OPA wasm-loader or @open-policy-agent/opa-wasm SDK usage.
 */
export async function evaluatePolicyWasm(input: any): Promise<{ allow: boolean; details?: any }> {
  if (!wasmInstance || !opaExports) return { allow: false, details: "WASM policy not loaded" };

  // The following is a conceptual example and will need adaptation per the exact WASM ABI:
  // 1. Serialize the `input` JSON into bytes and write to wasm memory using opaExports.opa_malloc
  // 2. Call the evaluation entrypoint (e.g., opa_eval) passing pointers to input/data
  // 3. Read the result from wasm memory and parse JSON
  //
  // Because OPA's wasm ABI is non-trivial, prefer using the official loader:
  //  - Node: use '@open-policy-agent/opa-wasm' or the opa wasm loader provided by OPA
  //  - Browser: use the same wasm loader adapted for browsers
  //
  // For now, we return a deny with an explanation to avoid unsafe assumptions.
  return { allow: false, details: "WASM evaluation placeholder - instantiate using official OPA wasm loader for production" };
}

/**
 * Public evaluate function: uses HTTP OPA when OPA_URL present, else attempts WASM
 */
export async function evaluatePolicy(input: any): Promise<{ allow: boolean; details?: any }> {
  if (OPA_URL) return evaluatePolicyHttp(input);
  return evaluatePolicyWasm(input);
}

/**
 * Convenience: if OPA_WASM_PATH env var is set, auto-load on startup.
 */
export async function autoLoadWasmFromEnv() {
  const p = process.env.OPA_WASM_PATH;
  if (p) {
    // path relative to project root
    const abs = path.isAbsolute(p) ? p : path.join(process.cwd(), p);
    await loadWasmPolicy(abs);
  }
}
