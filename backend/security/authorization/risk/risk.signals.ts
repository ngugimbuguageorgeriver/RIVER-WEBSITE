// RIVER WEBSITE/backend/authorization/risk/risk.signals.ts

/**
 * This is a signal adapter — where request context becomes risk signals.
 */

import { RiskSignal } from "./risk.model.ts";

export function collectRiskSignals(req, session): RiskSignal[] {
  const signals: RiskSignal[] = [];

  // IP change
  if (req.ip !== session.lastIp) {
    signals.push({
      type: "IP_ANOMALY",
      severity: 3,
      evidence: `IP changed to ${req.ip}`,
    });
  }

  // Device mismatch (soft signal — hard enforcement elsewhere)
  const deviceId = req.headers["x-device-id"];
  if (session.deviceId && deviceId !== session.deviceId) {
    signals.push({
      type: "DEVICE_MISMATCH",
      severity: 7,
      evidence: "Device header mismatch",
    });
  }

  // Suspicious velocity (example)
  if (req.headers["x-automation"] === "true") {
    signals.push({
      type: "BEHAVIOR_ANOMALY",
      severity: 6,
      evidence: "Automation header detected",
    });
  }

  return signals;
}
