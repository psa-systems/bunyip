-- BUNYIP-561: singleton branding record (id = 1), the one place the product
-- name, tagline, meta description and Open Graph image live.
--
-- Every column ships EMPTY on purpose. A migration is committed code, and
-- committed migrations are immutable, so seeding copy here would freeze the
-- brand in the repo permanently - which is the defect this table exists to
-- remove. An empty `brand_name` resolves to bunyip-api's `APP_NAME` (the
-- bootstrap default for a database that has never been branded); an empty
-- tagline / description / image URL means the corresponding markup is omitted.
CREATE TABLE branding (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    brand_name       TEXT NOT NULL DEFAULT '',
    tagline          TEXT NOT NULL DEFAULT '',
    meta_description TEXT NOT NULL DEFAULT '',
    og_image_url     TEXT NOT NULL DEFAULT '',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by       UUID REFERENCES users(id)
);

INSERT INTO branding (id) VALUES (1);
