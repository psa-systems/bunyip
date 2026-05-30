-- Stripe Overhaul: Remove locally-duplicated Stripe state
--
-- All subscription, payment, and invoice data is now fetched from the Stripe API.
-- Products and prices are managed through the admin panel via the Stripe API.
-- The stripe_config table retains only API key + webhook secret (encrypted).

-- Drop tables that duplicate Stripe state
DROP TABLE IF EXISTS payment_history;
DROP TABLE IF EXISTS invoices;
DROP TABLE IF EXISTS subscriptions;

-- Drop the invoice number sequence
DROP SEQUENCE IF EXISTS invoice_number_seq;

-- Remove price ID columns from stripe_config (prices now discovered from Stripe product metadata)
ALTER TABLE stripe_config
    DROP COLUMN IF EXISTS price_id_personal,
    DROP COLUMN IF EXISTS price_id_business;
