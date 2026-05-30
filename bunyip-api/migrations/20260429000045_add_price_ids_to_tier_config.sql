ALTER TABLE tier_config
  ADD COLUMN free_price_id          TEXT,
  ADD COLUMN early_adopter_price_id TEXT,
  ADD COLUMN standard_price_id      TEXT;
