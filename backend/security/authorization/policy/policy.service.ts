// RIVER WEBSITE/backend/authorization/policy/policy.service.ts

/**
 * policy.service.ts
 *
 * Evaluates PBAC/ABAC policies using OPA.
 * Supports:
 *  - HTTP OPA server evaluation (centralized)
 *  - WASM policy evaluation (local, embeddable) -- placeholder loader
 *  - OPA HTTP + WASM support
 *
 * Notes: to use WASM evaluation compile your Rego policy to Wasm and load it using the official OPA-WASM loader.
 */

import fetch from "node-fetch";
import fs from "fs";
import path from "path";

const OPA_URL = process.env.OPA_URL || "http://localhost:8181/v1/data/authz/allow";
const OPA_EVAL_TIMEOUT = 5000;

let wasmPolicy: any = null; // runtime cache for WASM evaluator (if loaded)

/**
 * Evaluate policy via OPA HTTP API
 */
export async function evaluatePolicyHttp(input: any): Promise<{ allow: boolean; details?: any }> {
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

/**
 * Load a compiled WASM policy into memory.
 * Expectation: You compile Rego to WASM (see instructions below) and place the .wasm file in disk.
 */
export function loadWasmPolicy(wasmPath: string) {
  if (!fs.existsSync(wasmPath)) throw new Error(`WASM policy not found at ${wasmPath}`);
  const buf = fs.readFileSync(wasmPath);
  // Placeholder: actual WASM initialization requires the OPA wasm SDK loader
  // e.g. const opaWasm = await opa.loadPolicy(buf); and create runtime.
  // We'll store the raw buffer for the placeholder.
  wasmPolicy = { buffer: buf, path: wasmPath };
}

/**
 * Evaluate policy using WASM runtime (placeholder). In production, use the OPA wasm SDK
 * or @open-policy-agent/opa-wasm package to instantiate runtime and evaluate.
 */
export async function evaluatePolicyWasm(input: any): Promise<{ allow: boolean; details?: any }> {
  if (!wasmPolicy) return { allow: false, details: "WASM policy not loaded" };

  // Placeholder: here you'd instantiate the runtime, set data and input, then call evaluate.
  // Returning deny by default when using placeholder.
  return { allow: false, details: "WASM evaluation not implemented in placeholder. Load and instantiate OPA WASM runtime." };
}

/**
 * Public helper: prefer HTTP OPA if OPA_URL defined, else fallback to WASM
 */
export async function evaluatePolicy(input: any): Promise<{ allow: boolean; details?: any }> {
  if (process.env.OPA_URL) {
    return evaluatePolicyHttp(input);
  }
  return evaluatePolicyWasm(input);
}

/**
 * Utility: Create input envelope for policies
 */
export function makePolicyInput(params: { user: any; resource: any; action: string; env?: any }) {
  return { user: params.user, resource: params.resource, action: params.action, env: params.env || {} };
}