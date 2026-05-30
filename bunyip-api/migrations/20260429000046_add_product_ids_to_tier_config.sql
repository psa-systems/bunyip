ALTER TABLE tier_config
  ADD COLUMN lifetime_product_id      TEXT,
  ADD COLUMN early_adopter_product_id TEXT,
  ADD COLUMN standard_product_id      TEXT;
