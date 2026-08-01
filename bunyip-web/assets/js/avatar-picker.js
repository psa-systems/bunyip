// BUNYIP-408: the client-side controller for every [data-avatar-picker] on the
// page. Mounted once from views::layout; a no-op when no picker is present.
// Markup + component CSS live in views::avatar_picker.
//
// BUNYIP-424: moved out of the AVATAR_PICKER_JS inline <script> constant so
// script-src can be 'self' with no 'unsafe-inline'.
(function () {
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
// Downscale + re-encode client-side, but never trust the result blindly: some
// browsers hand back an empty (0-byte) Blob from canvas.toBlob, which is truthy
// and would upload as an empty file ("The selected file is empty"). If the
// re-encode yields nothing usable, fall back to the original validated file -
// the API accepts png/jpeg/webp/gif and re-validates either way.
processImage(file,maxEdge).then(function(blob){
if(blob&&blob.size>0){upload(blob,'avatar.jpg');}else{upload(file,file.name||'avatar');}
}).catch(function(){upload(file,file.name||'avatar');});
});}
function upload(payload,name){if(!payload||!payload.size){setErr('That image could not be read. Please try a different file.');return;}
busy(true);setProgress(0);
var fd=new FormData();fd.append('avatar',payload,name);
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
})();
