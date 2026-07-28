//! BUNYIP-408: reusable avatar picker component.
//!
//! One component, mounted anywhere an image upload is needed. The markup
//! ([`avatar_picker`]) is progressive-enhancement friendly: without JS it is a
//! plain multipart `<form>` (choose a file, submit) plus a remove form; with JS,
//! [`AVATAR_PICKER_JS`] takes over and delivers the rich behaviour - the circle
//! is the primary click/drop target, selection previews instantly, the image is
//! validated (magic-byte MIME + 2 MB cap) and downscaled to a 512px square on a
//! canvas before it ever leaves the browser, and the upload fires automatically
//! with a progress ring. Component styling lives in `input.css`
//! (`.avatar-picker*`); the JS is mounted once from the base document head.
//!
//! Every avatar surface in the app renders a `[data-avatar-slot]` (see
//! `layout::avatar_badge`), so a successful upload/removal repaints the header
//! menu avatar too, with no full-page reload.

use maud::{html, Markup};

use crate::api::types::User;
use crate::views::ui::{button_class, icon};

/// Component CSS, mounted INLINE in the document head (see `layout::document`)
/// rather than compiled into `assets/styles.css`.
///
/// Why inline: `styles.css` is a separately-built, browser-cached file. A deploy
/// that ships fresh SSR HTML + inline JS but a stale/cached stylesheet would
/// leave every structural rule below undefined - the `absolute inset-0` fallback
/// initial then escaped its container and filled the whole card (BUNYIP-408 bug
/// report). Shipping these rules inline in the always-fresh SSR head removes the
/// stale-stylesheet failure mode entirely and needs no Tailwind rebuild. Keyed
/// on the theme tokens so light / dark / high-contrast all adapt. The markup
/// leans only on utilities that already exist in `styles.css`; everything novel
/// and structural lives here.
pub const AVATAR_PICKER_CSS: &str = r#".avatar-slot__img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:9999px}
.avatar-picker{display:flex;align-items:center;gap:1rem}
.avatar-picker__form{margin:0}
.avatar-picker__trigger{position:relative;display:inline-flex;align-items:center;justify-content:center;width:4rem;height:4rem;border-radius:9999px;cursor:pointer;flex:none}
.avatar-picker__input{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap;border:0}
.avatar-picker__circle{position:relative;width:100%;height:100%;border-radius:9999px;overflow:hidden;border:1px solid hsl(var(--border));background:hsl(var(--muted));display:flex;align-items:center;justify-content:center}
.avatar-picker__circle [data-avatar-initial]{user-select:none;-webkit-user-select:none}
.avatar-picker__overlay{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;border-radius:9999px;color:#fff;background:rgba(0,0,0,.55);font-size:.7rem;font-weight:600;opacity:0;transition:opacity .15s ease;pointer-events:none}
.avatar-picker__trigger:hover .avatar-picker__overlay,.avatar-picker__trigger:focus-within .avatar-picker__overlay,.avatar-picker.is-dragging .avatar-picker__overlay,.avatar-picker.is-uploading .avatar-picker__overlay{opacity:1}
.avatar-picker__trigger:focus-within .avatar-picker__circle{outline:2px solid var(--color-bunyip-reed-600);outline-offset:2px}
.avatar-picker.is-dragging .avatar-picker__circle{outline:2px dashed var(--color-bunyip-reed-500);outline-offset:2px;border-color:var(--color-bunyip-reed-500)}
.avatar-picker__progress{position:absolute;inset:-3px;border-radius:9999px;opacity:0;transition:opacity .15s ease;background:conic-gradient(var(--color-bunyip-reed-500) calc(var(--avatar-progress,0)*1%),transparent 0);-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 3px));mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 3px));pointer-events:none}
.avatar-picker.is-uploading .avatar-picker__progress{opacity:1}
.avatar-picker.is-uploading .avatar-picker__trigger{pointer-events:none;cursor:default}
.avatar-picker__side{display:flex;flex-direction:column;gap:.25rem;min-width:0}
.avatar-picker__actions{display:flex;flex-wrap:wrap;gap:.5rem}
.avatar-picker__help{font-size:.75rem;color:hsl(var(--muted-foreground));margin:0}
.avatar-picker__error{font-size:.75rem;color:hsl(var(--destructive));margin:0;min-height:1rem}
.avatar-picker__enhanced{display:none}
.avatar-picker[data-enhanced] .avatar-picker__enhanced{display:inline-flex}
.avatar-picker[data-enhanced] .avatar-picker__nojs{display:none}"#;

/// The client-side controller for every `[data-avatar-picker]` on the page.
/// Mounted once from `layout::document`. No-op when no picker is present.
pub const AVATAR_PICKER_JS: &str = r#"(function(){
var ALLOWED={'image/png':1,'image/jpeg':1,'image/webp':1,'image/gif':1};
function fmtSize(b){if(b>=1048576)return (b/1048576).toFixed(1)+' MB';if(b>=1024)return Math.round(b/1024)+' KB';return b+' B';}
function sniff(buf){var b=new Uint8Array(buf);
if(b.length>=4&&b[0]==0x89&&b[1]==0x50&&b[2]==0x4E&&b[3]==0x47)return 'image/png';
if(b.length>=3&&b[0]==0xFF&&b[1]==0xD8&&b[2]==0xFF)return 'image/jpeg';
if(b.length>=4&&b[0]==0x47&&b[1]==0x49&&b[2]==0x46&&b[3]==0x38)return 'image/gif';
if(b.length>=12&&b[0]==0x52&&b[1]==0x49&&b[2]==0x46&&b[3]==0x46&&b[8]==0x57&&b[9]==0x45&&b[10]==0x42&&b[11]==0x50)return 'image/webp';
return null;}
function renderSlot(slot,src){var initial=slot.querySelector('[data-avatar-initial]');var img=slot.querySelector('[data-avatar-image]');
if(src){if(!img){img=document.createElement('img');img.setAttribute('data-avatar-image','');img.className='avatar-slot__img';img.alt='Your profile photo';slot.appendChild(img);}img.src=src;img.style.display='';if(initial)initial.style.display='none';}
else{if(img)img.style.display='none';if(initial)initial.style.display='';}}
function updateAllSlots(src){var s=document.querySelectorAll('[data-avatar-slot]');for(var i=0;i<s.length;i++)renderSlot(s[i],src);}
function processImage(file,maxEdge){return createImageBitmap(file).then(function(bmp){
var side=Math.min(bmp.width,bmp.height),sx=(bmp.width-side)/2,sy=(bmp.height-side)/2,edge=Math.min(side,maxEdge);
var c=document.createElement('canvas');c.width=edge;c.height=edge;var ctx=c.getContext('2d');
// White backing so a transparent PNG/GIF flattens to white (not black) once
// encoded as JPEG. JPEG keeps the stored avatar small and is universally
// decodable; the API accepts png/jpeg/webp/gif so the exact choice is ours.
ctx.fillStyle='#ffffff';ctx.fillRect(0,0,edge,edge);
ctx.drawImage(bmp,sx,sy,side,side,0,0,edge,edge);if(bmp.close)bmp.close();
return new Promise(function(res){c.toBlob(res,'image/jpeg',0.85);});});}
var dropGuard=false;
function initPicker(root){
if(root.__avatarInit)return;root.__avatarInit=true;root.setAttribute('data-enhanced','');
var input=root.querySelector('[data-avatar-input]');
var circle=root.querySelector('[data-avatar-slot]');
var trigger=root.querySelector('[data-avatar-trigger]')||circle;
var errEl=root.querySelector('[data-avatar-error]');
var removeBtn=root.querySelector('[data-avatar-remove]');
var changeBtn=root.querySelector('[data-avatar-change]');
var uploadUrl=root.getAttribute('data-upload-url');
var removeUrl=root.getAttribute('data-remove-url');
var maxBytes=parseInt(root.getAttribute('data-max-bytes'),10)||2097152;
var maxEdge=parseInt(root.getAttribute('data-max-edge'),10)||512;
function setErr(m){if(errEl)errEl.textContent=m||'';}
function setProgress(p){root.style.setProperty('--avatar-progress',String(Math.round(p)));}
function busy(on){root.classList.toggle('is-uploading',!!on);if(changeBtn)changeBtn.disabled=!!on;if(removeBtn)removeBtn.disabled=!!on;}
function syncRemove(has){if(removeBtn){removeBtn.setAttribute('data-has-avatar',has?'1':'0');removeBtn.style.display=has?'':'none';}}
if(removeBtn)syncRemove(removeBtn.getAttribute('data-has-avatar')==='1');
if(changeBtn&&input)changeBtn.addEventListener('click',function(){input.click();});
function handleFile(file){setErr('');if(!file)return;
if(file.size>maxBytes){setErr('That image is '+fmtSize(file.size)+'. The limit is 2 MB.');return;}
var slice=file.slice(0,16);var read=slice.arrayBuffer?slice.arrayBuffer():new Response(slice).arrayBuffer();
Promise.resolve(read).then(function(buf){var mime=sniff(buf);
if(!mime||!ALLOWED[mime]){setErr('That file is not a PNG, JPEG, WebP, or GIF image.');return;}
// Preview with a data: URL (FileReader), not URL.createObjectURL - the page CSP
// is `img-src 'self' data: https:`, which blocks blob: URLs.
var fr=new FileReader();fr.onload=function(){renderSlot(circle,fr.result);};fr.readAsDataURL(file);
processImage(file,maxEdge).then(function(blob){if(!blob){setErr('Could not process that image.');return;}upload(blob);}).catch(function(){setErr('Could not read that image.');});
});}
function upload(blob){busy(true);setProgress(0);
var fd=new FormData();fd.append('avatar',blob,'avatar.jpg');
var xhr=new XMLHttpRequest();xhr.open('POST',uploadUrl);xhr.setRequestHeader('Accept','application/json');
if(xhr.upload)xhr.upload.onprogress=function(e){if(e.lengthComputable)setProgress(e.loaded/e.total*100);};
xhr.onload=function(){busy(false);
if(xhr.status>=200&&xhr.status<300){updateAllSlots('/me/avatar?v='+Date.now());syncRemove(true);setErr('');if(window.bunyipToast)window.bunyipToast('Profile photo updated','success');}
else{var msg='Upload failed. Please try again.';try{var j=JSON.parse(xhr.responseText);if(j&&j.error)msg=j.error;}catch(e){}setErr(msg);}};
xhr.onerror=function(){busy(false);setErr('Upload failed. Check your connection and try again.');};
xhr.send(fd);}
if(input)input.addEventListener('change',function(){if(input.files&&input.files[0])handleFile(input.files[0]);});
['dragenter','dragover'].forEach(function(ev){trigger.addEventListener(ev,function(e){e.preventDefault();root.classList.add('is-dragging');});});
trigger.addEventListener('dragleave',function(e){e.preventDefault();root.classList.remove('is-dragging');});
trigger.addEventListener('drop',function(e){e.preventDefault();root.classList.remove('is-dragging');var f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0];if(f)handleFile(f);});
if(!dropGuard){dropGuard=true;window.addEventListener('dragover',function(e){e.preventDefault();});window.addEventListener('drop',function(e){e.preventDefault();});}
if(removeBtn)removeBtn.addEventListener('click',function(){
if(removeBtn.getAttribute('data-has-avatar')!=='1')return;
if(!window.confirm('Remove your profile photo? This cannot be undone.'))return;
busy(true);var xhr=new XMLHttpRequest();xhr.open('POST',removeUrl);xhr.setRequestHeader('Accept','application/json');
xhr.onload=function(){busy(false);if(xhr.status>=200&&xhr.status<300){updateAllSlots(null);syncRemove(false);setErr('');if(window.bunyipToast)window.bunyipToast('Profile photo removed','success');}else{setErr('Could not remove the photo. Please try again.');}};
xhr.onerror=function(){busy(false);setErr('Could not remove the photo. Please try again.');};
xhr.send();});
}
function initAll(){var p=document.querySelectorAll('[data-avatar-picker]');for(var i=0;i<p.length;i++)initPicker(p[i]);}
if(document.readyState!=='loading')initAll();else document.addEventListener('DOMContentLoaded',initAll);
})();"#;

/// Render the avatar picker for `user`. Reusable: it carries its own endpoints
/// and limits via `data-*` attributes, so the controller wires it with no
/// per-instance config. The letter fallback (initial over a reed/water gradient)
/// shows when no avatar is set.
pub fn avatar_picker(user: &User) -> Markup {
    let src = user.avatar_src();
    let initial = user.avatar_initial();
    let has = src.is_some();
    html! {
        div class="avatar-picker"
            data-avatar-picker
            data-upload-url="/settings/avatar"
            data-remove-url="/settings/avatar/remove"
            data-max-bytes="2097152"
            data-max-edge="512" {
            // No-JS baseline: a real multipart form. JS hides its submit button
            // (`.avatar-picker__nojs`) and drives the upload instead.
            form class="avatar-picker__form" method="post" action="/settings/avatar" enctype="multipart/form-data" {
                label class="avatar-picker__trigger" data-avatar-trigger {
                    input type="file" name="avatar"
                          accept="image/png,image/jpeg,image/webp,image/gif"
                          class="avatar-picker__input" data-avatar-input
                          aria-label="Upload a profile photo (PNG, JPEG, WebP, or GIF, up to 2 MB)"
                          aria-describedby="avatar-picker-help avatar-picker-error";
                    span class="avatar-picker__circle" data-avatar-slot data-initial=(initial) {
                        @if let Some(s) = &src {
                            img src=(s) alt="Your profile photo" class="avatar-slot__img" data-avatar-image;
                        }
                        // `h-full w-full` (not `absolute inset-0`) so the letter
                        // fallback can never escape its circle even if this
                        // component's CSS is somehow missing.
                        span data-avatar-initial aria-hidden="true"
                             class="flex h-full w-full items-center justify-center rounded-full bg-gradient-to-br from-primary to-indigo-500 text-white text-xl font-semibold"
                             style=[has.then_some("display:none")] {
                            (initial)
                        }
                    }
                    span class="avatar-picker__overlay" aria-hidden="true" {
                        (icon("upload", "h-5 w-5"))
                        span { "Change" }
                    }
                    span class="avatar-picker__progress" data-avatar-progress aria-hidden="true" {}
                }
                // No-JS submit (hidden once enhanced).
                button type="submit" class=(button_class("outline", "sm", "avatar-picker__nojs mt-2")) {
                    (icon("upload", "mr-2 h-4 w-4")) "Upload"
                }
            }
            div class="avatar-picker__side" {
                div class="avatar-picker__actions" {
                    // JS-enhanced trigger (opens the same dialog).
                    button type="button" class=(button_class("outline", "sm", "avatar-picker__enhanced")) data-avatar-change {
                        (icon("upload", "mr-2 h-4 w-4")) "Change photo"
                    }
                    // JS remove (confirm + delete without reload); hidden until
                    // an avatar exists.
                    button type="button"
                           class=(button_class("ghost", "sm", "avatar-picker__enhanced text-destructive hover:text-destructive"))
                           data-avatar-remove data-has-avatar=(if has { "1" } else { "0" }) {
                        (icon("trash", "mr-2 h-4 w-4")) "Remove photo"
                    }
                    // No-JS remove form (hidden once enhanced), only when set.
                    @if has {
                        form method="post" action="/settings/avatar/remove" class="avatar-picker__nojs" {
                            button type="submit" class=(button_class("ghost", "sm", "text-destructive hover:text-destructive")) {
                                (icon("trash", "mr-2 h-4 w-4")) "Remove photo"
                            }
                        }
                    }
                }
                p id="avatar-picker-help" class="avatar-picker__help" { "PNG, JPEG, WebP, or GIF up to 2 MB." }
                p id="avatar-picker-error" class="avatar-picker__error" data-avatar-error role="status" aria-live="polite" {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::avatar_picker;
    use crate::api::types::User;

    fn user(avatar: Option<&str>) -> User {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "ada@example.com",
            "role": "subscriber",
            "email_verified": true,
            "two_factor_enabled": false,
            "membership_status": "none",
            "price_locked": false,
            "created_at": "2026-01-01T00:00:00Z",
            "subscription_tier": "standard",
            "lifetime_member": false,
            "first_name": "Ada",
            "avatar_updated_at": avatar,
        }))
        .expect("valid user json")
    }

    #[test]
    fn renders_picker_scaffolding_and_endpoints() {
        let html = avatar_picker(&user(None)).into_string();
        assert!(html.contains("data-avatar-picker"));
        assert!(html.contains(r#"data-upload-url="/settings/avatar""#));
        assert!(html.contains(r#"data-remove-url="/settings/avatar/remove""#));
        // A live region for errors + a hidden focusable input for a11y.
        assert!(html.contains(r#"aria-live="polite""#));
        assert!(html.contains(r#"type="file""#));
    }

    #[test]
    fn empty_state_shows_initial_and_hides_no_remove() {
        // No avatar -> letter fallback visible, remove button flagged empty, and
        // no no-JS remove form (nothing to remove).
        let html = avatar_picker(&user(None)).into_string();
        assert!(html.contains(">A</span>") || html.contains(">A<"));
        assert!(html.contains(r#"data-has-avatar="0""#));
        assert!(!html.contains(r#"action="/settings/avatar/remove""#));
    }

    #[test]
    fn set_state_renders_image_and_remove_affordances() {
        let html = avatar_picker(&user(Some("2026-07-28T10:00:00Z"))).into_string();
        assert!(html.contains("data-avatar-image"));
        assert!(html.contains("/me/avatar?v="));
        assert!(html.contains(r#"data-has-avatar="1""#));
        // No-JS remove form present when an avatar exists.
        assert!(html.contains(r#"action="/settings/avatar/remove""#));
    }
}
