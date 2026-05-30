CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invoice_number VARCHAR NOT NULL UNIQUE,
    amount_cents INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR NOT NULL DEFAULT 'usd',
    description TEXT NOT NULL,
    pdf_storage_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invoices_user_id ON invoices(user_id);
CREATE SEQUENCE invoice_number_seq START 1;
