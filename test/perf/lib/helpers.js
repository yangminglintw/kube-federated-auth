import { check } from "k6";

// Build a TokenReview JSON payload
export function buildTokenReviewPayload(token) {
  return JSON.stringify({
    apiVersion: "authentication.k8s.io/v1",
    kind: "TokenReview",
    spec: { token: token },
  });
}

// Request params for TokenReview endpoint with caller auth
export function tokenReviewParams(callerToken) {
  return {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${callerToken}`,
    },
  };
}

// Reusable check assertions for TokenReview responses
export function checkTokenReview(res) {
  return check(res, {
    "status is 200": (r) => r.status === 200,
    "authenticated is true": (r) => {
      try {
        return r.json().status.authenticated === true;
      } catch (e) {
        return false;
      }
    },
  });
}
