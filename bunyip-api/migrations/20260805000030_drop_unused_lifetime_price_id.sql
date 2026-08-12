-- BUNYIP-517: drop the unused `lifetime_price_id` column.
--
-- The lifetime tier is granted as a $0 subscription on `free_price_id` (see
-- `live_free_price_id` and the free/lifetime grant paths), and its Stripe
-- product for webhook classification is `lifetime_product_id`, now derived from
-- the mapped free price on save. `lifetime_price_id` (added in
-- 20260429000045_add_price_ids_to_tier_config.sql) was never read by any
-- resolver or written by any form, so it is a redundant source of truth. Free
-- and lifetime share one $0 price; there is no separate lifetime price to store.
ALTER TABLE tier_config DROP COLUMN IF EXISTS lifetime_price_id;
