-- Add app_tag to stripe_config for filtering Stripe products by application.
-- NULL falls back to the STRIPE_APP_TAG env var (default: "a8n-tools").
ALTER TABLE stripe_config ADD COLUMN app_tag TEXT;
