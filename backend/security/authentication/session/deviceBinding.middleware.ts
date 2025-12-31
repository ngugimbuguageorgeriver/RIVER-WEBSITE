// RIVER WEBSITE/backend/authentication/session/deviceBinding.middleware.ts

/**
 * DEVICE BINDING (SESSION HIJACK PREVENTION)
 * 📍 Session model already supports this - deviceId?: string;
 * 
 * Attach Early - app.use(requireSession, enforceDeviceBinding); -> 🔥 Prevents token replay across devices.
 */

export function enforceDeviceBinding(request, reply) {
    const session = req.session;
    const deviceId = req.headers["x-device-id"];
  
    if (!deviceId || deviceId !== session.deviceId) {
      return res.status(401).json({ message: "Device mismatch" });
    }
  
  }
  