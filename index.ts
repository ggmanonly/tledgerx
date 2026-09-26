// LedgerX PayPal webhook handler.
//
// This is the ONLY thing allowed to change a user's plan. It:
//   1. Receives the raw event PayPal sends when a subscription changes.
//   2. Calls PayPal's own API to verify the event is genuinely from PayPal
//      (never trust a webhook body without this step — anyone could POST
//      a fake "subscription activated" event otherwise).
//   3. Uses the Supabase service-role key (server-only, never shipped to
//      the browser) to update the paying user's row in `profiles`.
//
// Deploy with:  supabase functions deploy paypal-webhook --no-verify-jwt
// (--no-verify-jwt because PayPal calls this anonymously, not as a logged-in user)
//
// Required secrets (supabase secrets set NAME=value):
//   PAYPAL_CLIENT_ID        PayPal REST app client id
//   PAYPAL_SECRET           PayPal REST app secret
//   PAYPAL_WEBHOOK_ID       Webhook ID shown when you create the webhook in the PayPal dashboard
//   PAYPAL_ENV              "sandbox" or "live"
//   PAYPAL_PLAN_ID_PRO      Billing Plan ID for the Pro subscription
//   PAYPAL_PLAN_ID_QUANT    Billing Plan ID for the Quant subscription
//   SB_SERVICE_ROLE_KEY     Your Supabase project's service_role key (Project Settings → API)
// SUPABASE_URL is provided automatically by the Edge Functions runtime.

import { createClient } from "jsr:@supabase/supabase-js@2";

const PAYPAL_CLIENT_ID = Deno.env.get("PAYPAL_CLIENT_ID") ?? "";
const PAYPAL_SECRET = Deno.env.get("PAYPAL_SECRET") ?? "";
const PAYPAL_WEBHOOK_ID = Deno.env.get("PAYPAL_WEBHOOK_ID") ?? "";
const PAYPAL_ENV = (Deno.env.get("PAYPAL_ENV") ?? "sandbox").toLowerCase();
const PAYPAL_PLAN_ID_PRO = Deno.env.get("PAYPAL_PLAN_ID_PRO") ?? "";
const PAYPAL_PLAN_ID_QUANT = Deno.env.get("PAYPAL_PLAN_ID_QUANT") ?? "";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE_KEY = Deno.env.get("SB_SERVICE_ROLE_KEY") ?? "";

const PAYPAL_API = PAYPAL_ENV === "live"
  ? "https://api-m.paypal.com"
  : "https://api-m.sandbox.paypal.com";

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

async function getPaypalAccessToken(): Promise<string> {
  const basic = btoa(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`);
  const res = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!res.ok) throw new Error(`PayPal OAuth failed: ${res.status}`);
  const json = await res.json();
  return json.access_token as string;
}

async function verifySignature(headers: Headers, rawBody: string, accessToken: string): Promise<boolean> {
  const payload = {
    auth_algo: headers.get("paypal-auth-algo"),
    cert_url: headers.get("paypal-cert-url"),
    transmission_id: headers.get("paypal-transmission-id"),
    transmission_sig: headers.get("paypal-transmission-sig"),
    transmission_time: headers.get("paypal-transmission-time"),
    webhook_id: PAYPAL_WEBHOOK_ID,
    webhook_event: JSON.parse(rawBody),
  };
  const res = await fetch(`${PAYPAL_API}/v1/notifications/verify-webhook-signature`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) return false;
  const json = await res.json();
  return json.verification_status === "SUCCESS";
}

function planFromPlanId(planId: string): "pro" | "quant" | null {
  if (planId === PAYPAL_PLAN_ID_PRO) return "pro";
  if (planId === PAYPAL_PLAN_ID_QUANT) return "quant";
  return null;
}

Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }
  if (!PAYPAL_CLIENT_ID || !PAYPAL_SECRET || !PAYPAL_WEBHOOK_ID || !SERVICE_ROLE_KEY) {
    console.error("paypal-webhook: missing required secrets");
    return new Response("Server not configured", { status: 500 });
  }

  const rawBody = await req.text();

  let accessToken: string;
  try {
    accessToken = await getPaypalAccessToken();
  } catch (err) {
    console.error("PayPal OAuth error:", err);
    return new Response("Upstream auth failed", { status: 502 });
  }

  const verified = await verifySignature(req.headers, rawBody, accessToken).catch((err) => {
    console.error("Signature verification error:", err);
    return false;
  });
  if (!verified) {
    console.warn("paypal-webhook: signature verification failed, rejecting event");
    return new Response("Invalid signature", { status: 400 });
  }

  const event = JSON.parse(rawBody);
  const type = event.event_type as string;
  const resource = event.resource ?? {};

  try {
    if (type === "BILLING.SUBSCRIPTION.ACTIVATED") {
      const userId = resource.custom_id as string | undefined;
      const plan = planFromPlanId(resource.plan_id as string);
      if (userId && plan) {
        const { error } = await admin.from("profiles").update({
          plan,
          status: "active",
          paypal_subscription_id: resource.id,
          updated_at: new Date().toISOString(),
        }).eq("id", userId);
        if (error) throw error;
      } else {
        console.warn("ACTIVATED event missing custom_id or unrecognized plan_id", resource.plan_id);
      }
    } else if (type === "BILLING.SUBSCRIPTION.CANCELLED" || type === "BILLING.SUBSCRIPTION.EXPIRED") {
      const { error } = await admin.from("profiles").update({
        status: "cancelled",
        plan: "base",
        updated_at: new Date().toISOString(),
      }).eq("paypal_subscription_id", resource.id);
      if (error) throw error;
    } else if (type === "BILLING.SUBSCRIPTION.SUSPENDED") {
      const { error } = await admin.from("profiles").update({
        status: "suspended",
        updated_at: new Date().toISOString(),
      }).eq("paypal_subscription_id", resource.id);
      if (error) throw error;
    } else if (type === "BILLING.SUBSCRIPTION.PAYMENT.FAILED") {
      const { error } = await admin.from("profiles").update({
        status: "past_due",
        updated_at: new Date().toISOString(),
      }).eq("paypal_subscription_id", resource.id);
      if (error) throw error;
    } else {
      // Other event types (e.g. PAYMENT.SALE.COMPLETED for a renewal) are
      // safe to ignore for now — subscription state is already covered above.
      console.log("paypal-webhook: unhandled event type", type);
    }
  } catch (err) {
    console.error("paypal-webhook: database update failed", err);
    // Still return 200 below is wrong here — let PayPal retry a real failure.
    return new Response("Database update failed", { status: 500 });
  }

  return new Response("OK", { status: 200 });
});
