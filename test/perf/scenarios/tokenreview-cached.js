import http from "k6/http";
import {
  buildTokenReviewPayload,
  tokenReviewParams,
  checkTokenReview,
} from "../lib/helpers.js";

const BASE_URL = __ENV.BASE_URL || "kube-federated-auth";
const CALLER_TOKEN = __ENV.CALLER_TOKEN;
const REVIEW_TOKEN_A = __ENV.REVIEW_TOKEN_A;

export const options = {
  scenarios: {
    // Phase 1: Cold request to populate cache
    warmup: {
      executor: "shared-iterations",
      vus: 1,
      iterations: 1,
      startTime: "0s",
    },
    // Phase 2: Sustained load hitting cache
    cached_load: {
      executor: "constant-arrival-rate",
      rate: 50,
      timeUnit: "1s",
      duration: "20s",
      preAllocatedVUs: 5,
      maxVUs: 20,
      startTime: "2s",
    },
  },
  thresholds: {
    "http_req_duration{scenario:cached_load}": ["p(95)<100", "p(99)<200"],
    "http_req_failed{scenario:cached_load}": ["rate<0.01"],
  },
};

export default function () {
  const payload = buildTokenReviewPayload(REVIEW_TOKEN_A);
  const params = tokenReviewParams(CALLER_TOKEN);

  const res = http.post(
    `http://${BASE_URL}/apis/authentication.k8s.io/v1/tokenreviews`,
    payload,
    params
  );

  checkTokenReview(res);
}
