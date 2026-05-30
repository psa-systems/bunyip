-- Add stripe_payment_method_id to users so we can record the authorized payment method
-- captured during signup card authorization.
ALTER TABLE users ADD COLUMN stripe_payment_method_id VARCHAR(255);
