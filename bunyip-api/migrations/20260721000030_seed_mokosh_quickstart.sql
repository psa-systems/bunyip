-- PMS-662: Mokosh product quick-start, delivered as a bunyip per-app doc for the
-- mokosh-server application (rendered at /apps/mokosh-server/docs/quick-start).
-- High-level onboarding tour grounded in the actual module set (auth via Bunyip
-- SSO, tenants, contacts, tickets, time/mileage/projects/calendar/dispatch, SLA
-- policies/targets, settings; portal + reports are the only 501 stubs).
-- sort_order -1 so the quick start sorts ahead of the other mokosh-server pages
-- (the entry point). Idempotent via ON CONFLICT so a re-run is safe.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'quick-start', 'Quick start', $md$
# Mokosh quick start

Mokosh is a PSA (Professional Services Automation) platform for MSPs: run your client work, contacts, time, and service levels in one place. This is a high-level tour to get oriented after a fresh install.

## 1. Run it

Stand up an instance with Docker Compose (the server plus its database), then the web frontend. See [Running with Docker Compose](/apps/mokosh-server/docs/docker-compose); for larger setups, [Splitting the server and web across hosts](/apps/mokosh-server/docs/split-deployment).

## 2. Sign in

Mokosh signs you in through Bunyip - single sign-on, no separate Mokosh password. Open the web app and sign in with your Bunyip account.

- An account on a configured platform-admin domain becomes a **super admin** and manages every tenant.
- Everyone else is placed into their own **tenant** - their MSP organization - on first sign-in.

## 3. Set up the organization (super admins)

A **tenant** is one MSP organization. Super admins create and manage tenants (create, edit, suspend, reactivate). Inside a tenant, that org's data and users are isolated from every other tenant.

## 4. Add your clients

Under **Contacts**, record the people and companies you do work for. Contacts are what tickets and work attach to.

## 5. Do the work: tickets

**Tickets** are the unit of work - a request, incident, or task for a client - tracked through their lifecycle. Around a ticket you capture the rest of delivery:

- **Time tracking** and **mileage** - log the time and travel spent.
- **Projects**, the **calendar**, and **dispatch** - plan and schedule larger work.
- **Notes and attachments** - keep the context on the record.

## 6. Service levels (SLA)

Define **SLA policies** with response and resolution **targets**, honouring your **business hours** and **holiday calendars**. Mokosh applies them to tickets and a background sweep tracks them, so a looming or missed target surfaces instead of slipping quietly.

## 7. Settings

**Settings** hold the tenant-level configuration that tunes the PSA to how you work: the service-level targets above, per-module configuration, and email / notification setup.

## Where next

- [Running with Docker Compose](/apps/mokosh-server/docs/docker-compose) and [Configuration](/apps/mokosh-server/docs/configuration) for deployment detail.
- [The image registry and signing in](/apps/mokosh-server/docs/registry-login) for how image pulls are authenticated.
$md$, -1
FROM applications WHERE slug = 'mokosh-server'
ON CONFLICT (application_id, slug) DO NOTHING;
