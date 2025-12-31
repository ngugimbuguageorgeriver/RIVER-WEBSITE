//

/** */

import axios from "axios";

const OPA_URL = process.env.OPA_URL || "http://localhost:8181";

export const opaClient = {
  async decide(payload: { input: any }) {
    const res = await axios.post(
      `${OPA_URL}/v1/data/authz/adaptive`,
      payload
    );

    return res.data.result;
  },
};
