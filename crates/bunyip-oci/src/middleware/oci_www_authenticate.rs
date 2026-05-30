//! Adds `WWW-Authenticate: Bearer ...` to every 401 response on the OCI App.
//!
//! Docker clients follow the realm advertised here to hit `/auth/token`
//! with Basic auth and exchange for a registry JWT.

use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::sync::Arc;

use crate::config::OciConfig;

pub struct OciWwwAuthenticate {
    pub cfg: Arc<OciConfig>,
}

impl<S, B> Transform<S, ServiceRequest> for OciWwwAuthenticate
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = OciWwwAuthenticateMw<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(OciWwwAuthenticateMw {
            service,
            cfg: self.cfg.clone(),
        })
    }
}

pub struct OciWwwAuthenticateMw<S> {
    service: S,
    cfg: Arc<OciConfig>,
}

impl<S, B> Service<ServiceRequest> for OciWwwAuthenticateMw<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let cfg = self.cfg.clone();
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            if resp.status() == actix_web::http::StatusCode::UNAUTHORIZED {
                let header = format!(
                    "Bearer realm=\"https://{service}/auth/token\",service=\"{service}\"",
                    service = cfg.service
                );
                if let Ok(hv) = actix_web::http::header::HeaderValue::from_str(&header) {
                    resp.headers_mut()
                        .insert(actix_web::http::header::WWW_AUTHENTICATE, hv);
                }
            }
            Ok(resp.map_into_left_body())
        })
    }
}
