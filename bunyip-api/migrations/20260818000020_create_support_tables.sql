-- BUNYIP-571: inbound support queue. A support_ticket is one conversation with
-- an external sender (often not yet a customer); support_messages are the
-- inbound replies and the app-composed outbound replies, threaded by mail
-- Message-ID. The inbound poller (slice 3) matches an incoming reply's
-- In-Reply-To / References against support_messages.message_id to attach it to
-- an existing ticket, else opens a new one. Distinct from `feedback` (an HTTP
-- form from a known visitor); support items originate from mail and carry the
-- threading headers feedback has no column for.
CREATE TABLE support_tickets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject         TEXT NOT NULL,
    requester_email VARCHAR(255) NOT NULL,
    requester_name  VARCHAR(255),
    status          VARCHAR(20) NOT NULL DEFAULT 'open',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_message_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_support_tickets_status ON support_tickets(status);
CREATE INDEX idx_support_tickets_requester_email ON support_tickets(requester_email);
CREATE INDEX idx_support_tickets_last_message_at ON support_tickets(last_message_at DESC);

CREATE TABLE support_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id       UUID NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
    direction       VARCHAR(10) NOT NULL,
    from_email      VARCHAR(255) NOT NULL,
    to_email        VARCHAR(255),
    body_text       TEXT NOT NULL,
    body_html       TEXT,
    -- RFC 5322 Message-ID of this email (angle-bracket form). Unique when
    -- present, so a re-polled message is stored at most once and an inbound
    -- reply can be threaded by matching against it.
    message_id      TEXT,
    in_reply_to     TEXT,
    -- The References header chain, space-separated Message-IDs. `references` is
    -- a SQL reserved word, so the column is mail_references.
    mail_references TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_support_messages_ticket_id ON support_messages(ticket_id);
-- Partial unique index: dedupe real Message-IDs, allow many NULLs.
CREATE UNIQUE INDEX idx_support_messages_message_id
    ON support_messages(message_id) WHERE message_id IS NOT NULL;
