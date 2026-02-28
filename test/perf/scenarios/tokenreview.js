import http from "k6/http";
import { sleep } from "k6";
import {
  buildTokenReviewPayload,
  tokenReviewParams,
  checkTokenReview,
} from "../lib/helpers.js";

const BASE_URL = __ENV.BASE_URL || "kube-federated-auth";
const CALLER_TOKEN = __ENV.CALLER_TOKEN;
const REVIEW_TOKEN_A = __ENV.REVIEW_TOKEN_A;
const REVIEW_TOKEN_B = __ENV.REVIEW_TOKEN_B;

export const options = {
  scenarios: {
    tokenreview_rampup: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "10s", target: 5 },
        { duration: "20s", target: 10 },
        { duration: "10s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<2000", "p(99)<3000"],
  },
};

export default function () {
  // Alternate between cluster-a and cluster-b tokens
  const token = __VU % 2 === 0 ? REVIEW_TOKEN_A : REVIEW_TOKEN_B;
  const payload = buildTokenReviewPayload(token);
  const params = tokenReviewParams(CALLER_TOKEN);

  const res = http.post(
    `http://${BASE_URL}/apis/authentication.k8s.io/v1/tokenreviews`,
    payload,
    params
  );

  checkTokenReview(res);
  sleep(0.1);
}
