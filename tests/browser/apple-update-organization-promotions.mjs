import { runPromotionCases } from "./apple-update-promotions.mjs";

export default async function run(browser,record) {
 return runPromotionCases(browser,record,["groups", "empty-groups", "ready", "overlap", "unknown", "error", "exception", "incompatible", "pilot-only", "viewer", "receipt", "history", "receipt-site-operator", "preview-site-operator", "long"],true);
}
