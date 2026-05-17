use axum::{http::StatusCode, Json};
use serde::Serialize;

pub fn ok<T: Serialize>(body: T) -> (StatusCode, Json<T>) {
    (StatusCode::OK, Json(body))
}

pub fn created<T: Serialize>(body: T) -> (StatusCode, Json<T>) {
    (StatusCode::CREATED, Json(body))
}

#[derive(Debug, Serialize)]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
}

impl<T> Paginated<T> {
    pub fn new(items: Vec<T>, total: usize, page: u32, per_page: u32) -> Self {
        Self {
            items,
            total,
            page,
            per_page,
        }
    }
}
