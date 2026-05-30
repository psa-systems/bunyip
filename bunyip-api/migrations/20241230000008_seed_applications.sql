-- Seed initial applications
INSERT INTO applications (name, slug, display_name, description, container_name, health_check_url, source_code_url, version)
VALUES
    ('rus', 'rus', 'RUS - URL Shortener', 'Fast, simple URL shortening with QR code generation. Built with Rust for maximum performance.', 'rus', 'http://rus:8080/health', 'https://github.com/example/rus', '1.0.0'),
    ('rustylinks', 'rustylinks', 'Rusty Links', 'Bookmark management made simple. Organize, tag, and access your bookmarks from anywhere.', 'rustylinks', 'http://rustylinks:8080/health', 'https://github.com/example/rustylinks', '1.0.0');
