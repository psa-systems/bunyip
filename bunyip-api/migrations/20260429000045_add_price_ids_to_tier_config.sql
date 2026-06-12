ALTER TABLE tier_config
  ADD COLUMN free_price_id          TEXT,
  -- The lifetime tier is sold as a one-time Stripe price; carry its price id
  -- alongside the recurring tiers so it pairs with lifetime_product_id added in
  -- 20260429000046_add_product_ids_to_tier_config.sql.
  ADD COLUMN lifetime_price_id      TEXT,
  ADD COLUMN early_adopter_price_id TEXT,
  ADD COLUMN standard_price_id      TEXT;
