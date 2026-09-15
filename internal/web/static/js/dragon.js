/* ─────────────────────────────────────────────────────────────
   Quetzalog mascot — a small feathered dragon assembled from
   colorful building blocks. All brand uses (login, empty states,
   loading, 404, logo lockup) render from these one source so the
   mascot can be swapped for richer artwork without app changes.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";

  var C = {
    head: "#10B981", body: "#0B9E6E", dark: "#059669", darker: "#047857",
    belly1: "#FDE68A", belly2: "#FCD34D",
    horn1: "#F59E0B", horn2: "#FBBF24",
    wing1: "#14B8A6", wing2: "#06B6D4", ear: "#06B6D4",
    ink: "#0B1220", eye: "#FFFFFF", cheek: "#F87171",
  };

  /* Feather plume: seven individually visible colored blocks fanning
     from the tail pivot (88,54). Each block: 9×20 rounded brick. */
  var FEATHERS = [
    { a: -78, c: "#EF4444" },
    { a: -62, c: "#F97316" },
    { a: -46, c: "#F59E0B" },
    { a: -30, c: "#FDE047" },
    { a: -14, c: "#10B981" },
    { a: 2, c: "#06B6D4" },
    { a: 18, c: "#3B82F6" },
  ];

  function feather() {
    return FEATHERS.map(function (f) {
      return '<rect class="dr-blk" x="-4.5" y="-21" width="9" height="20" rx="3.5" fill="' + f.c +
        '" transform="translate(88 54) rotate(' + f.a + ')"/>';
    }).join("");
  }

  function dragonBody(cls) {
    var o = { size: 100, cls: cls || "" };
    return feather() +
      '<rect class="dr-blk" x="80" y="48" width="12" height="18" rx="5" fill="' + C.dark + '" transform="rotate(18 86 57)"/>' +
      '<rect class="dr-blk" x="46" y="38" width="38" height="40" rx="14" fill="' + C.body + '"/>' +
      '<rect class="dr-blk" x="66" y="30" width="14" height="18" rx="5" fill="' + C.wing1 + '" transform="rotate(14 73 39)"/>' +
      '<rect class="dr-blk" x="76" y="36" width="12" height="15" rx="4.5" fill="' + C.wing2 + '" transform="rotate(26 82 43.5)"/>' +
      '<rect class="dr-blk" x="50" y="50" width="24" height="9" rx="4" fill="' + C.belly1 + '"/>' +
      '<rect class="dr-blk" x="52" y="61" width="20" height="9" rx="4" fill="' + C.belly2 + '"/>' +
      '<rect class="dr-blk" x="54" y="72" width="16" height="7" rx="3.5" fill="' + C.belly1 + '"/>' +
      '<rect class="dr-blk" x="26" y="22" width="32" height="28" rx="11" fill="' + C.head + '"/>' +
      '<rect class="dr-blk" x="33" y="10" width="9" height="12" rx="3.5" fill="' + C.horn1 + '" transform="rotate(-14 37.5 16)"/>' +
      '<rect class="dr-blk" x="46" y="8" width="9" height="12" rx="3.5" fill="' + C.horn2 + '" transform="rotate(6 50.5 14)"/>' +
      '<rect class="dr-blk" x="58" y="20" width="9" height="12" rx="4" fill="' + C.ear + '" transform="rotate(18 62.5 26)"/>' +
      '<circle class="dr-blk" cx="38" cy="35" r="6.5" fill="' + C.eye + '"/>' +
      '<circle class="dr-blk" cx="36.5" cy="35.5" r="3.4" fill="' + C.ink + '"/>' +
      '<circle class="dr-blk" cx="38.6" cy="33.6" r="1.3" fill="' + C.eye + '"/>' +
      '<circle class="dr-blk" cx="31" cy="42.5" r="2.2" fill="' + C.cheek + '" opacity="0.55"/>' +
      '<path class="dr-blk" d="M29 42 q3.5 3 7.5 1.5" stroke="' + C.ink + '" stroke-width="1.6" fill="none" stroke-linecap="round"/>' +
      '<rect class="dr-blk" x="44" y="50" width="9" height="13" rx="4" fill="' + C.dark + '"/>' +
      '<rect class="dr-blk" x="50" y="76" width="13" height="9" rx="4" fill="' + C.dark + '"/>' +
      '<rect class="dr-blk" x="66" y="76" width="13" height="9" rx="4" fill="' + C.darker + '"/>';
  }

  /* Full mascot. size = rendered px width; assemble plays the
     block-assembly animation once. Decorative by default. */
  function dragon(opts) {
    var size = (opts && opts.size) || 96;
    var cls = "ql-dragon " + ((opts && opts.cls) || "");
    var a11y = opts && opts.deco === false
      ? 'role="img" aria-label="Quetzalog dragon mascot"'
      : 'aria-hidden="true"';
    return '<svg class="' + cls + '" viewBox="0 0 100 100" width="' + size + '" height="' + size + '" ' + a11y + ">" +
      dragonBody() + "</svg>";
  }

  /* Simplified dragon head — app icon / avatar / favicon. */
  function dragonHead(size) {
    size = size || 32;
    return '<svg viewBox="0 0 32 32" width="' + size + '" height="' + size + '" aria-hidden="true">' +
      '<rect x="22" y="4" width="4.5" height="9" rx="2" fill="#EF4444" transform="rotate(18 24 8.5)"/>' +
      '<rect x="25.5" y="6" width="4.5" height="9" rx="2" fill="#F59E0B" transform="rotate(10 27.7 10.5)"/>' +
      '<rect x="28.5" y="9" width="4.5" height="9" rx="2" fill="#06B6D4" transform="rotate(4 30.7 13.5)"/>' +
      '<rect x="6" y="8" width="21" height="18.5" rx="6.5" fill="#10B981"/>' +
      '<rect x="9.5" y="3" width="5" height="7.5" rx="2.2" fill="#F59E0B" transform="rotate(-12 12 6.7)"/>' +
      '<rect x="16" y="2" width="5" height="7.5" rx="2.2" fill="#FBBF24" transform="rotate(6 18.5 5.7)"/>' +
      '<circle cx="13" cy="16.5" r="3.6" fill="#fff"/>' +
      '<circle cx="12.2" cy="16.8" r="1.9" fill="#0B1220"/>' +
      '<circle cx="13.6" cy="15.6" r="0.7" fill="#fff"/>' +
      '<path d="M9.5 21 q2.5 2 5.5 1" stroke="#0B1220" stroke-width="1.3" fill="none" stroke-linecap="round"/>' +
      "</svg>";
  }

  /* Geometric "Q" mark: a ring with a three-block feather tail. */
  function qMark(size) {
    size = size || 30;
    return '<svg viewBox="0 0 32 32" width="' + size + '" height="' + size + '" aria-hidden="true">' +
      '<circle cx="14" cy="14" r="9.5" fill="none" stroke="#10B981" stroke-width="5.5" pathLength="100" ' +
      'stroke-dasharray="91 9" stroke-dashoffset="-40.5" stroke-linecap="round"/>' +
      '<rect x="19.5" y="17.5" width="5" height="8" rx="2" fill="#06B6D4" transform="rotate(38 22 21.5)"/>' +
      '<rect x="22.5" y="20.5" width="5" height="8" rx="2" fill="#F59E0B" transform="rotate(38 25 24.5)"/>' +
      "</svg>";
  }

  /* Primary lockup: [logo] Quetzalog */
  function logo(opts) {
    var tagline = opts && opts.tagline !== false;
    return '<a class="brand" href="#/overview" aria-label="Quetzalog — Overview">' +
      '<span class="brand-mark"><img src="/static/images/upleft2.png" width="45" height="45" alt="" aria-hidden="true"></span>' +
      "<span><span class='brand-name'>Quetzalog</span>" +
      (tagline ? "<span class='brand-tag'>SEE MORE. SOLVE FASTER.</span>" : "") +
      "</span></a>";
  }

  window.QL = window.QL || {};
  window.QL.dragon = dragon;
  window.QL.dragonHead = dragonHead;
  window.QL.qMark = qMark;
  window.QL.logo = logo;
})();
