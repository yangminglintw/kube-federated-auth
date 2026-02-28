import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BASE_URL || "kube-federated-auth";

export const options = {
  scenarios: {
    health_baseline: {
      executor: "constant-arrival-rate",
      rate: 100,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 10,
      maxVUs: 50,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<50", "p(99)<100"],
  },
};

export default function () {
  const res = http.get(`http://${BASE_URL}/health`);
  check(res, {
    "status is 200": (r) => r.status === 200,
    "body has ok": (r) => r.json().status === "ok",
  });
}
