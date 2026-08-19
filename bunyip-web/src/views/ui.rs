//! Maud UI helpers (buttons, inline lucide icons, badges, boxes). The toolkit
//! moved to the shared `web-kit` crate (BUNYIP-502); re-exported here so every
//! `crate::views::ui::*` call site is unchanged.
//!
//! Two things stay in bunyip-web: the `#[cfg(test)] pub` assertion helpers the
//! page tests import as `crate::views::ui::assert_*`, and the guard tests that
//! must scan bunyip-web's own `src/` tree (icon names, amber contrast, arrow
//! glyphs, the primary-text token) or `include_str!` its built CSS. Rooting
//! them here keeps them covering every caller, which all still live in this
//! crate; the toolkit itself carries the small unit tests of its own helpers.

pub use web_kit::ui::*;

/// BUNYIP-421 regression guard, shared by the page tests. `truncate` is
/// `overflow:hidden` + `text-overflow:ellipsis` + `white-space:nowrap`, and the
/// latter two do nothing on a flex/grid container: its items keep their
/// max-content width and any sibling past the container's edge is clipped away
/// with no ellipsis. So `truncate` belongs on the text element itself, never on
/// a class list that also turns the element into a flex/grid box. Panics naming
/// the offending class attribute.
#[cfg(test)]
pub fn assert_no_truncating_flex_container(html: &str) {
    for attr in html.split("class=\"").skip(1) {
        let Some(classes) = attr.split('"').next() else {
            continue;
        };
        let tokens: Vec<&str> = classes.split_whitespace().collect();
        let boxes_children = tokens
            .iter()
            .any(|t| matches!(*t, "flex" | "inline-flex" | "grid" | "inline-grid"));
        assert!(
            !(tokens.contains(&"truncate") && boxes_children),
            "`truncate` on a flex/grid container clips its siblings instead of \
             ellipsising the text (BUNYIP-421); move it to the text span: \
             class=\"{classes}\""
        );
    }
}

/// BUNYIP-367 regression guard, shared by the dashboard page tests. Sibling
/// cards are separated by the page's 24px rhythm - `gap-6` on a card grid,
/// `space-y-6` on a card stack. A container that lays its cards out with no
/// spacing utility leaves their 1px borders touching, which reads as cards
/// overlapping by a pixel or two instead of being spaced; a negative margin on
/// a card overlaps it with its neighbour outright. Panics naming the offending
/// class attribute.
#[cfg(test)]
pub fn assert_cards_are_spaced(html: &str) {
    // Tags that never have a closing tag, so they never open a frame.
    const VOID: [&str; 9] = [
        "area", "br", "col", "hr", "img", "input", "link", "meta", "source",
    ];

    let is =
        |t: &str, util: &str| t == util || t.strip_suffix(util).is_some_and(|p| p.ends_with(':'));
    // (class attribute of the open element, how many direct card children it has)
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        let Some(gt) = rest[lt..].find('>') else {
            break;
        };
        let tag = &rest[lt + 1..lt + gt];
        rest = &rest[lt + gt + 1..];
        if tag.starts_with('!') {
            continue; // <!DOCTYPE html>
        }
        if tag.starts_with('/') {
            if let Some((classes, cards)) = stack.pop() {
                assert!(
                    cards < 2
                        || classes
                            .split_whitespace()
                            .any(|t| is(t, "gap-6") || is(t, "space-y-6")),
                    "a container of {cards} sibling cards must space them on the page's \
                     24px rhythm (gap-6 / space-y-6), else their borders touch and the \
                     cards read as overlapping (BUNYIP-367): class=\"{classes}\""
                );
            }
            continue;
        }
        let name = tag.split([' ', '\t', '\n', '/']).next().unwrap_or("");
        let classes = tag
            .split_once("class=\"")
            .and_then(|(_, a)| a.split('"').next())
            .unwrap_or("");
        if classes.split_whitespace().any(|t| t == "bg-card") {
            assert!(
                !classes
                    .split_whitespace()
                    .any(|t| t.starts_with("-m") || t.contains(":-m")),
                "a negative margin on a card pulls it over its neighbour \
                 (BUNYIP-367): class=\"{classes}\""
            );
            if let Some((_, cards)) = stack.last_mut() {
                *cards += 1;
            }
        }
        if !tag.ends_with('/') && !VOID.contains(&name) {
            stack.push((classes.to_string(), 0));
        }
    }
}

#[cfg(test)]
mod tests {
    /// BUNYIP-502: the source-scanning guards below must cover both this crate's
    /// `src/` AND the extracted `web-kit` toolkit, which now holds the icon /
    /// badge markup lifted out of `views`. Without this second root a typo'd
    /// icon name or a sub-AA amber added in web-kit would slip the scan.
    fn web_kit_src() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/web-kit/src")
    }

    // -- BUNYIP-485: primary-as-foreground contrast --------------------------
    //
    // `--primary` is the button FILL. Used as text it measured 1.6:1 on the
    // dark card, so every foreground use moved to `--primary-text` (the same
    // split `--destructive` / `--destructive-text` already uses).

    /// Body of the first `selector` block in `input.css` that defines
    /// `--primary-text` (skips the later same-selector blocks that only carry
    /// the static `--color-*` overrides).
    fn theme_block<'a>(css: &'a str, selector: &str) -> &'a str {
        let mut rest = css;
        loop {
            let at = rest
                .find(selector)
                .unwrap_or_else(|| panic!("input.css has no `{selector}` block"));
            let start = at + selector.len();
            let end = start
                + rest[start..]
                    .find("\n}")
                    .unwrap_or_else(|| panic!("unterminated `{selector}` block"));
            if rest[start..end].contains("--primary-text:") {
                return &rest[start..end];
            }
            rest = &rest[end..];
        }
    }

    /// sRGB components (0..1) of an `H S% L%` token declared in `block`.
    fn token(block: &str, name: &str) -> [f64; 3] {
        let prefix = format!("{name}:");
        let line = block
            .lines()
            .find(|l| l.trim_start().starts_with(&prefix))
            .unwrap_or_else(|| panic!("`{name}` missing from theme block"));
        let mut parts = line
            .rsplit(':')
            .next()
            .expect("token value")
            .trim()
            .trim_end_matches(';')
            .split_whitespace()
            .map(|p| {
                p.trim_end_matches('%')
                    .parse::<f64>()
                    .expect("numeric HSL component")
            });
        let (h, s, l) = (
            parts.next().expect("hue"),
            parts.next().expect("saturation") / 100.0,
            parts.next().expect("lightness") / 100.0,
        );
        let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
        let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
        let m = l - c / 2.0;
        let (r, g, b) = match (h / 60.0) as u32 % 6 {
            0 => (c, x, 0.0),
            1 => (x, c, 0.0),
            2 => (0.0, c, x),
            3 => (0.0, x, c),
            4 => (x, 0.0, c),
            _ => (c, 0.0, x),
        };
        [r + m, g + m, b + m]
    }

    /// `fg` painted over `bg` at `alpha` (what `bg-primary/10` composites to).
    fn mix(fg: [f64; 3], bg: [f64; 3], alpha: f64) -> [f64; 3] {
        std::array::from_fn(|i| fg[i] * alpha + bg[i] * (1.0 - alpha))
    }

    fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
        let luminance = |c: [f64; 3]| {
            let f = |v: f64| {
                if v <= 0.03928 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])
        };
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    /// WCAG 2.1 AA for normal text against every surface `text-primary-text`
    /// can land on, in all four theme blocks, including the `bg-primary/10`
    /// icon bubbles (the fill composited onto the surface).
    #[test]
    fn primary_text_token_meets_aa_on_every_surface() {
        let css = include_str!("../../input.css");
        for (selector, theme) in [
            (":root {", "light"),
            ("\n.dark {", "dark"),
            ("\n.high-contrast {", "high-contrast"),
            (".dark.high-contrast {", "dark.high-contrast"),
        ] {
            let block = theme_block(css, selector);
            let text = token(block, "--primary-text");
            let fill = token(block, "--primary");
            for surface in ["--card", "--background", "--muted"] {
                let bg = token(block, surface);
                // 0 is the bare surface; the rest are every `*-primary/<n>`
                // wash the views paint over it (bubbles, gradients, panels).
                for wash in [0, 5, 10, 18, 20] {
                    let against = mix(fill, bg, f64::from(wash) / 100.0);
                    let ratio = contrast(text, against);
                    assert!(
                        ratio >= 4.5,
                        "{theme}: --primary-text on {surface} under a {wash}% \
                         --primary wash is {ratio:.2}:1, below AA 4.5:1"
                    );
                }
            }
        }
    }

    // -- BUNYIP-548: amber text over its own tint ----------------------------
    //
    // The `warning` badge paints amber text on a 15% amber-500 wash. The wash
    // lightens the surface beneath the text, so the ratio has to be measured
    // against the composite rather than the bare surface: amber-700 came to
    // 4.49:1 on the light card and 4.18:1 on the page background, both under
    // AA for the badge's 12px type. amber-800 clears every surface.

    /// sRGB (0..1) of `oklch(L% C H)`, the form Tailwind v4 declares its stock
    /// scales in. Out-of-gamut components clamp, as the browser does.
    fn oklch(l: f64, c: f64, h: f64) -> [f64; 3] {
        let (a, b) = (c * h.to_radians().cos(), c * h.to_radians().sin());
        let cube = |v: f64| v * v * v;
        let (lc, mc, sc) = (
            cube(l + 0.3963377774 * a + 0.2158037573 * b),
            cube(l - 0.1055613458 * a - 0.0638541728 * b),
            cube(l - 0.0894841775 * a - 1.2914855480 * b),
        );
        [
            4.0767416621 * lc - 3.3077115913 * mc + 0.2309699292 * sc,
            -1.2684380046 * lc + 2.6097574011 * mc - 0.3413193965 * sc,
            -0.0041960863 * lc - 0.7034186147 * mc + 1.7076147010 * sc,
        ]
        .map(|v| {
            let v = v.clamp(0.0, 1.0);
            if v <= 0.0031308 {
                12.92 * v
            } else {
                1.055 * v.powf(1.0 / 2.4) - 0.055
            }
        })
    }

    /// `--color-amber-<step>` as the built stylesheet declares it, so the check
    /// reads the palette that actually ships rather than a remembered hex.
    fn amber(step: &str) -> [f64; 3] {
        let css = include_str!("../../assets/styles.css");
        let decl = format!("--color-amber-{step}:oklch(");
        let at = css.find(&decl).unwrap_or_else(|| {
            panic!("`--color-amber-{step}` missing from assets/styles.css; rebuild it with `bun run build:css`")
        }) + decl.len();
        let body = &css[at..at + css[at..].find(')').expect("closed `oklch(`")];
        let mut parts = body.split_whitespace().map(|p| {
            p.trim_end_matches('%')
                .parse::<f64>()
                .expect("numeric oklch component")
        });
        oklch(
            parts.next().expect("lightness") / 100.0,
            parts.next().expect("chroma"),
            parts.next().expect("hue"),
        )
    }

    /// Every amber utility in one class list, split by theme half: the wash
    /// alpha (0 when the element carries no tint of its own) and the text steps
    /// the half paints, since one class list can carry more than one.
    fn amber_utilities(classes: &str) -> (f64, Vec<String>, Vec<String>) {
        let (wash_p, light_p, dark_p) = (
            concat!("bg-", "amber-500/"),
            concat!("text-", "amber-"),
            concat!("dark:text-", "amber-"),
        );
        let (mut wash, mut light, mut dark) = (0.0, Vec::new(), Vec::new());
        for raw in classes.split_whitespace() {
            let tok = raw.trim_matches(|c: char| {
                !c.is_ascii_alphanumeric() && c != '-' && c != '/' && c != ':'
            });
            if let Some(pct) = tok.strip_prefix(wash_p) {
                wash = pct.parse::<f64>().expect("numeric wash alpha") / 100.0;
            } else if let Some(step) = tok.strip_prefix(dark_p) {
                dark.push(step.to_string());
            } else if let Some(step) = tok.strip_prefix(light_p) {
                light.push(step.to_string());
            }
        }
        (wash, light, dark)
    }

    /// AA for every amber text step in `classes`, measured against its own wash
    /// over both surfaces an amber element lands on, in all four theme blocks.
    fn assert_amber_meets_aa(site: &str, classes: &str) {
        let css = include_str!("../../input.css");
        let (wash, light, dark) = amber_utilities(classes);
        let fill = amber("500");
        for (selector, theme, is_dark) in [
            (":root {", "light", false),
            ("\n.dark {", "dark", true),
            ("\n.high-contrast {", "high-contrast", false),
            (".dark.high-contrast {", "dark.high-contrast", true),
        ] {
            let block = theme_block(css, selector);
            let steps = if is_dark { &dark } else { &light };
            for step in steps {
                let text = amber(step);
                for surface in ["--card", "--background"] {
                    let against = mix(fill, token(block, surface), wash);
                    let ratio = contrast(text, against);
                    assert!(
                        ratio >= 4.5,
                        "{site}: {theme} amber-{step} on {surface} under a \
                         {:.0}% amber-500 wash is {ratio:.2}:1, below AA 4.5:1",
                        wash * 100.0
                    );
                }
            }
        }
    }

    /// The badge's own tint is what pushed its text under AA, so the check runs
    /// against the classes the rendered badge actually carries.
    #[test]
    fn warning_badge_text_meets_aa_over_its_own_tint() {
        let markup = super::badge("warning", "Stale dataset").into_string();
        let classes = markup
            .split("class=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("badge renders a class attribute");
        let (wash, light, dark) = amber_utilities(classes);
        assert!(wash > 0.0, "warning badge lost its tint: {classes}");
        assert_eq!(light.len(), 1, "one light amber step: {classes}");
        assert_eq!(dark.len(), 1, "one dark amber step: {classes}");
        assert_amber_meets_aa("badge(\"warning\")", classes);
    }

    /// Same rule wherever else the views paint amber text, tinted or not: a
    /// class list is one composite, so a wash on the line applies to the text
    /// on it. Keeps the next amber surface from landing under AA unnoticed.
    #[test]
    fn every_amber_text_use_meets_aa() {
        let needle = concat!("text-", "amber-");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src, web_kit_src()];
        let mut checked = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable source dir") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let body = std::fs::read_to_string(&path).expect("readable source file");
                    for (n, line) in body.lines().enumerate() {
                        if line.contains(needle) {
                            assert_amber_meets_aa(&format!("{}:{}", path.display(), n + 1), line);
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert!(
            checked > 0,
            "the amber scan matched nothing; needle is stale"
        );
    }

    /// The suffix-less spelling of the utility paints the fill colour, so
    /// `text-primary-text` is the only correct foreground in any view.
    #[test]
    fn no_view_uses_the_fill_colour_as_a_foreground() {
        // Split so this file's own source does not match the scan.
        let needle = concat!("text-", "primary");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src, web_kit_src()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable source dir") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let body = std::fs::read_to_string(&path).expect("readable source file");
                    if body
                        .match_indices(needle)
                        .any(|(i, _)| !body[i + needle.len()..].starts_with('-'))
                    {
                        offenders.push(path);
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "`{needle}` is the fill colour and fails AA in dark mode; \
             use `{needle}-text`: {offenders:?}"
        );
    }

    /// BUNYIP-550: an arrow written as a literal character renders in the body
    /// font and cannot be sized or coloured with the surrounding icon classes,
    /// so it is never the arrow. Every view, marketing skin included, uses
    /// [`icon`] (`arrow-left` / `arrow-right`); BUNYIP-554 retired the Font
    /// Awesome `<i>` the skin used to carry. The needles are `\u{}` escapes so
    /// this file's own source does not match.
    #[test]
    fn no_view_hardcodes_an_arrow_character() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src, web_kit_src()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable source dir") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let body = std::fs::read_to_string(&path).expect("readable source file");
                    if body.contains('\u{2190}') || body.contains('\u{2192}') {
                        offenders.push(path);
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "literal arrow characters render in the body font; use `icon(\"arrow-left\")` / \
             `icon(\"arrow-right\")`: {offenders:?}"
        );
    }

    /// BUNYIP-554: `inner()` answers `""` for a name it does not know, so a
    /// typo renders an empty `<svg>` - the icon just vanishes, with nothing in
    /// a log and nothing on screen to say why. Every literal name passed to
    /// [`icon`] anywhere in the tree must resolve. This is what keeps the
    /// glyphs the Font Awesome removal moved inline from silently disappearing.
    #[test]
    fn every_icon_name_used_in_the_views_resolves() {
        // Split so this file's own `icon(` definition does not match the scan.
        let needle = concat!("icon", "(\"");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src, web_kit_src()];
        let (mut checked, mut offenders) = (0, Vec::new());
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable source dir") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let body = std::fs::read_to_string(&path).expect("readable source file");
                for (n, line) in body.lines().enumerate() {
                    // Comments and assertion prose name the shape; only code
                    // emits it (same cut as the security scan).
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    for piece in line.split(needle).skip(1) {
                        let Some(name) = piece.split('"').next() else {
                            continue;
                        };
                        checked += 1;
                        if !web_kit::ui::icon_is_known(name) {
                            offenders.push(format!(
                                "{}:{}: icon(\"{name}\")",
                                path.display(),
                                n + 1
                            ));
                        }
                    }
                }
            }
        }
        assert!(
            checked > 20,
            "the icon scan matched {checked} sites; needle is stale"
        );
        assert!(
            offenders.is_empty(),
            "unknown icon name renders an empty <svg>; add it to `inner()`:\n{}",
            offenders.join("\n")
        );
    }
}
