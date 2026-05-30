//! Billing route configuration

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/billing")
            .route(
                "/setup-intent",
                web::post().to(handlers::create_setup_intent),
            )
            .route("/invoices", web::get().to(handlers::list_invoices))
            .route(
                "/invoices/{invoice_id}/download",
                web::get().to(handlers::download_invoice),
            ),
    );
}
