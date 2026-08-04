// Drag-and-drop + keyboard reordering for admin lists (BUNYIP-473).
//
// Opt-in through markup so script-src stays 'self' (BUNYIP-424 pattern):
//   [data-reorder-list][data-reorder-action]  the container; POST target for the new order
//   [data-reorder-item][data-app-id]           each draggable row
//   [data-reorder-handle]                       the drag handle (also the keyboard target)
//
// A drag only starts from the handle, so the row's own controls (toggles, Edit)
// stay clickable. On drop, or on ArrowUp/ArrowDown while a handle is focused, the
// row moves and the new id order is POSTed as {ordered_ids:[...]}. Nothing
// navigates, so the list never scroll-jumps - the bug this fixes.
(function () {
  var lists = document.querySelectorAll('[data-reorder-list]');
  Array.prototype.forEach.call(lists, initList);

  function items(list) {
    return Array.prototype.slice.call(list.querySelectorAll('[data-reorder-item]'));
  }

  function persist(list) {
    var action = list.getAttribute('data-reorder-action');
    if (!action) return;
    var ids = items(list).map(function (r) { return r.getAttribute('data-app-id'); });
    fetch(action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ ordered_ids: ids }),
    })
      .then(function (r) {
        if (!r.ok) throw new Error('reorder failed');
        if (window.bunyipToast) window.bunyipToast('Order saved', 'success');
      })
      .catch(function () {
        if (window.bunyipToast) window.bunyipToast('Could not save the new order', 'error');
        // The server is the source of truth; reload to show the real order.
        setTimeout(function () { window.location.reload(); }, 900);
      });
  }

  function initList(list) {
    var dragging = null;
    var armed = false; // a drag only proceeds when it began on the handle

    list.addEventListener('pointerdown', function (e) {
      armed = !!(e.target.closest && e.target.closest('[data-reorder-handle]'));
    });

    list.addEventListener('dragstart', function (e) {
      var row = e.target.closest && e.target.closest('[data-reorder-item]');
      if (!row || !armed) {
        e.preventDefault(); // a drag that did not start on the handle is cancelled
        return;
      }
      dragging = row;
      row.classList.add('opacity-50');
      if (e.dataTransfer) {
        e.dataTransfer.effectAllowed = 'move';
        // Firefox will not start a drag unless some data is set.
        try { e.dataTransfer.setData('text/plain', row.getAttribute('data-app-id') || ''); } catch (_) {}
      }
    });

    list.addEventListener('dragover', function (e) {
      if (!dragging) return;
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
      var over = e.target.closest && e.target.closest('[data-reorder-item]');
      if (!over || over === dragging || over.parentNode !== list) return;
      var rect = over.getBoundingClientRect();
      var after = e.clientY - rect.top > rect.height / 2;
      // Live move: the dragged row physically shifts to where it would drop, so
      // it is its own drop indicator (no separate indicator element needed).
      if (after) list.insertBefore(dragging, over.nextSibling);
      else list.insertBefore(dragging, over);
    });

    list.addEventListener('dragend', function () {
      if (!dragging) return;
      dragging.classList.remove('opacity-50');
      dragging = null;
      armed = false;
      persist(list);
    });

    // Keyboard path: ArrowUp/ArrowDown on a focused handle move its row.
    list.addEventListener('keydown', function (e) {
      var handle = e.target.closest && e.target.closest('[data-reorder-handle]');
      if (!handle) return;
      if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
      var row = handle.closest('[data-reorder-item]');
      if (!row) return;
      var moved = false;
      if (e.key === 'ArrowUp' && row.previousElementSibling) {
        list.insertBefore(row, row.previousElementSibling);
        moved = true;
      } else if (e.key === 'ArrowDown' && row.nextElementSibling) {
        list.insertBefore(row.nextElementSibling, row);
        moved = true;
      }
      if (moved) {
        e.preventDefault();
        handle.focus(); // keep focus on the moved row's handle
        persist(list);
      }
    });
  }
})();
