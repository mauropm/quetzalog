/* ─────────────────────────────────────────────────────────────
   Quetzalog icon set — single thin geometric family (24×24,
   stroke-based). The only illustrative asset in the product is
   the dragon mascot; everything else is this icon set.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";

  var P = "fill='none' stroke='currentColor' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'";

  var ICONS = {
    dashboard: '<rect x="3" y="3" width="7.5" height="9" rx="1.5" ' + P + '/><rect x="13.5" y="3" width="7.5" height="5.5" rx="1.5" ' + P + '/><rect x="13.5" y="12" width="7.5" height="9" rx="1.5" ' + P + '/><rect x="3" y="15.5" width="7.5" height="5.5" rx="1.5" ' + P + '/>',
    search: '<circle cx="11" cy="11" r="7" ' + P + '/><path d="m20 20-3.5-3.5" ' + P + '/>',
    blocks: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5" ' + P + '/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5" ' + P + '/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5" ' + P + '/><path d="M17 14v6M14 17h6" ' + P + '/>',
    queue: '<path d="M4 6h10M4 12h7M4 18h9" ' + P + '/><path d="m14.5 15.5 2 2 3.5-4" ' + P + '/><circle cx="19.5" cy="5.5" r="1.8" ' + P + '/>',
    investigate: '<circle cx="11" cy="11" r="6.5" ' + P + '/><path d="M11 4.5V7M11 15v2.5M4.5 11H7M15 11h2.5" ' + P + '/><path d="m20.5 20.5-4-4" ' + P + '/>',
    shield: '<path d="M12 3 5 5.8v5.4c0 4.4 3 7.6 7 9.3 4-1.7 7-4.9 7-9.3V5.8Z" ' + P + '/>',
    shieldAlert: '<path d="M12 3 5 5.8v5.4c0 4.4 3 7.6 7 9.3 4-1.7 7-4.9 7-9.3V5.8Z" ' + P + '/><path d="M12 8.5v4" ' + P + '/><circle cx="12" cy="15.8" r="0.9" fill="currentColor" stroke="none"/>',
    gauge: '<path d="M5.2 18.5a8.5 8.5 0 1 1 13.6 0" ' + P + '/><path d="m12 13 3.5-3.5" ' + P + '/><circle cx="12" cy="13" r="1.6" ' + P + '/>',
    entities: '<circle cx="6" cy="6" r="2.5" ' + P + '/><circle cx="18" cy="6" r="2.5" ' + P + '/><circle cx="12" cy="18" r="2.5" ' + P + '/><path d="M8.4 7.2 10.8 16M15.6 7.2 13.2 16M8.5 6h7" ' + P + '/>',
    crosshair: '<circle cx="12" cy="12" r="8" ' + P + '/><path d="M12 2.5V7M12 17v4.5M2.5 12H7M17 12h4.5" ' + P + '/>',
    settings: '<circle cx="12" cy="12" r="3" ' + P + '/><path d="M12 2.8 13 5.4a7 7 0 0 1 2 1l2.6-.8 1.7 3-1.9 1.9a7 7 0 0 1 0 2l1.9 1.9-1.7 3-2.6-.8a7 7 0 0 1-2 1l-1 2.6-3.4 0-1-2.6a7 7 0 0 1-2-1l-2.6.8-1.7-3 1.9-1.9a7 7 0 0 1 0-2L4.3 8.2l1.7-3 2.6.8a7 7 0 0 1 2-1l1-2.6Z" ' + P + '/>',
    user: '<circle cx="12" cy="8" r="3.8" ' + P + '/><path d="M5 20c.8-3.4 3.6-5.2 7-5.2s6.2 1.8 7 5.2" ' + P + '/>',
    bell: '<path d="M18 9.5a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6" ' + P + '/><path d="M10.3 19a2 2 0 0 0 3.4 0" ' + P + '/>',
    help: '<circle cx="12" cy="12" r="8.5" ' + P + '/><path d="M9.6 9.3a2.5 2.5 0 1 1 3.7 2.2c-.8.4-1.3 1-1.3 1.9" ' + P + '/><circle cx="12" cy="16.8" r="0.9" fill="currentColor" stroke="none"/>',
    logout: '<path d="M14 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7" ' + P + '/><path d="m16 8 4 4-4 4M20 12H9.5" ' + P + '/>',
    "chevron-down": '<path d="m6 9.5 6 6 6-6" ' + P + '/>',
    "chevron-right": '<path d="m9.5 6 6 6-6 6" ' + P + '/>',
    "chevron-left": '<path d="m14.5 6-6 6 6 6" ' + P + '/>',
    plus: '<path d="M12 5v14M5 12h14" ' + P + '/>',
    x: '<path d="M6 6l12 12M18 6 6 18" ' + P + '/>',
    check: '<path d="m4.5 12.5 5 5L19.5 7" ' + P + '/>',
    clock: '<circle cx="12" cy="12" r="8.5" ' + P + '/><path d="M12 7v5l3.5 2" ' + P + '/>',
    filter: '<path d="M4 5h16l-6.2 7.2V19l-3.6-2v-4.8Z" ' + P + '/>',
    link: '<path d="M9.5 14.5 14.5 9.5" ' + P + '/><path d="M11 6.8 13 4.8a4 4 0 0 1 5.7 5.7l-2 2" ' + P + '/><path d="M13 17.2 11 19.2a4 4 0 0 1-5.7-5.7l2-2" ' + P + '/>',
    note: '<path d="M7 3.5h7L18.5 8v11a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 19V5A1.5 1.5 0 0 1 7 3.5Z" ' + P + '/><path d="M13.5 3.5V8.5H18.5M8.5 12.5h6M8.5 16h4" ' + P + '/>',
    play: '<path d="M8 5.5v13l10-6.5Z" ' + P + '/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2" ' + P + '/><path d="M5.5 14.5A2.5 2.5 0 0 1 3 12V5.5A2.5 2.5 0 0 1 5.5 3H12a2.5 2.5 0 0 1 2.5 2.5" ' + P + '/>',
    warning: '<path d="M12 4 2.8 19.5h18.4Z" ' + P + '/><path d="M12 9.5v4.5" ' + P + '/><circle cx="12" cy="16.8" r="0.9" fill="currentColor" stroke="none"/>',
    info: '<circle cx="12" cy="12" r="8.5" ' + P + '/><path d="M12 11v5.5" ' + P + '/><circle cx="12" cy="7.8" r="0.9" fill="currentColor" stroke="none"/>',
    "arrow-right": '<path d="M4.5 12h15M13.5 6l6 6-6 6" ' + P + '/>',
    "arrow-left": '<path d="M19.5 12h-15M10.5 6l-6 6 6 6" ' + P + '/>',
    more: '<circle cx="5.5" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="18.5" cy="12" r="1.2" fill="currentColor" stroke="none"/>',
    refresh: '<path d="M4.5 12a7.5 7.5 0 0 1 13-5l1.6 1.6M19.5 12a7.5 7.5 0 0 1-13 5l-1.6-1.6" ' + P + '/><path d="M19.5 3.5V8H15M4.5 20.5V16H9" ' + P + '/>',
    eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" ' + P + '/><circle cx="12" cy="12" r="3" ' + P + '/>',
    zap: '<path d="M13 3 4.5 13.5H11L9.5 21 19 10h-6.5Z" ' + P + '/>',
    database: '<ellipse cx="12" cy="5.5" rx="7.5" ry="3" ' + P + '/><path d="M4.5 5.5v13c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-13" ' + P + '/><path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3" ' + P + '/>',
    server: '<rect x="3.5" y="4" width="17" height="7" rx="2" ' + P + '/><rect x="3.5" y="13" width="17" height="7" rx="2" ' + P + '/><circle cx="7.5" cy="7.5" r="0.9" fill="currentColor" stroke="none"/><circle cx="7.5" cy="16.5" r="0.9" fill="currentColor" stroke="none"/>',
    globe: '<circle cx="12" cy="12" r="8.5" ' + P + '/><path d="M3.5 12h17M12 3.5c2.5 2.4 3.8 5.4 3.8 8.5S14.5 18.1 12 20.5c-2.5-2.4-3.8-5.4-3.8-8.5S9.5 5.9 12 3.5Z" ' + P + '/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2.5" ' + P + '/><rect x="10" y="10" width="4" height="4" rx="1" ' + P + '/><path d="M12 2.5V6M12 18v3.5M2.5 12H6M18 12h3.5M5 5.5 6.8 7.3M18 5.5 16.2 7.3" ' + P + '/>',
    key: '<circle cx="8.5" cy="14.5" r="4.5" ' + P + '/><path d="m12 11 8-8M16 7l3 3M13.5 9.5l2.5 2.5" ' + P + '/>',
    terminal: '<rect x="3" y="4" width="18" height="16" rx="2.5" ' + P + '/><path d="m7 9 3.5 3L7 15M13 15h4" ' + P + '/>',
    calendar: '<rect x="3.5" y="5" width="17" height="16" rx="2.5" ' + P + '/><path d="M3.5 9.5h17M8 2.5V6M16 2.5V6" ' + P + '/>',
    users: '<circle cx="9" cy="8" r="3.2" ' + P + '/><path d="M3.5 19.5c.7-3 2.9-4.6 5.5-4.6s4.8 1.6 5.5 4.6" ' + P + '/><path d="M15.5 5.2a3.2 3.2 0 0 1 0 5.9M17.5 15.3c1.7.6 2.8 2 3.2 4.2" ' + P + '/>',
    activity: '<path d="M3 12h4l2.5-6 4 12 2.5-6H21" ' + P + '/>',
    bug: '<path d="M9 6.5a3 3 0 0 1 6 0V11M7.5 8.5 5 7M16.5 8.5 19 7M4.5 13H7M17 13h2.5M6 17.5 8 16M18 17.5 16 16" ' + P + '/><rect x="7.5" y="10.5" width="9" height="9.5" rx="4.5" ' + P + '/>',
    download: '<path d="M12 3.5V15M7.5 11 12 15.5 16.5 11" ' + P + '/><path d="M4.5 17.5v1.5a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-1.5" ' + P + '/>',
    trash: '<path d="M4.5 6.5h15M9.5 3.5h5M6.5 6.5 7.5 20a1.5 1.5 0 0 0 1.5 1.4h6A1.5 1.5 0 0 0 16.5 20l1-13.5M10 10.5v7M14 10.5v7" ' + P + '/>',
    edit: '<path d="M14.5 5 19 9.5 8 20.5H3.5V16Z" ' + P + '/><path d="m12.5 7 4.5 4.5" ' + P + '/>',
    command: '<path d="M9 9V5.5A2.5 2.5 0 0 0 4 5.5v13a2.5 2.5 0 0 0 5 0V9Zm6 0v-3.5A2.5 2.5 0 0 1 20 5.5v13a2.5 2.5 0 0 1-5 0V9Z" ' + P + '/><path d="M9 9h6v6H9Z" ' + P + '/>',
    external: '<path d="M14 4.5h5.5V10" ' + P + '/><path d="M19.5 4.5 11 13M9 4.5H6a2 2 0 0 0-2 2V18a2 2 0 0 0 2 2h11.5a2 2 0 0 0 2-2v-3" ' + P + '/>',
    layers: '<path d="m12 3 9 5-9 5-9-5Z" ' + P + '/><path d="m4.6 12.5 7.4 4.1 7.4-4.1M4.6 16.5 12 20.5l7.4-4" ' + P + '/>',
    target: '<circle cx="12" cy="12" r="8.5" ' + P + '/><circle cx="12" cy="12" r="4.8" ' + P + '/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/>',
    host: '<rect x="3.5" y="5" width="17" height="13" rx="2.5" ' + P + '/><path d="M7.5 9v4M12 9v4M16.5 9v4" ' + P + '/><path d="M8 21h8" ' + P + '/>',
    ip: '<circle cx="12" cy="12" r="8.5" ' + P + '/><path d="M12 3.5c2.2 2.2 3.4 5.2 3.4 8.5S14.2 18.3 12 20.5M3.5 12h17M5 7.5c2 1.6 4.6 2.5 7 2.5s5-.9 7-2.5M5 16.5c2-1.6 4.6-2.5 7-2.5s5 .9 7 2.5" ' + P + '/>',
    process: '<rect x="4" y="7" width="16" height="12" rx="2.5" ' + P + '/><path d="M8 3.5V7M14 3.5V7M8 11v4M12 11v4M16 11v4" ' + P + '/>',
    file: '<path d="M7 3.5h7L18.5 8v11a1.5 1.5 0 0 1-1.5 1.5H7A1.5 1.5 0 0 1 5.5 19V5A1.5 1.5 0 0 1 7 3.5Z" ' + P + '/><path d="M13.5 3.5V8.5H18.5" ' + P + '/>',
    domain: '<circle cx="12" cy="12" r="8.5" ' + P + '/><path d="M3.5 12h17M12 3.5c-2.4 2.3-3.6 5.3-3.6 8.5s1.2 6.2 3.6 8.5" ' + P + '/><circle cx="8" cy="8.5" r="1" fill="currentColor" stroke="none"/>',
    sun: '<circle cx="12" cy="12" r="4" ' + P + '/><path d="M12 2.5V5M12 19v2.5M4.5 12H2M22 12h-2.5M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M18.4 5.6l-1.8 1.8M7.4 16.6l-1.8 1.8" ' + P + '/>',
    moon: '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5Z" ' + P + '/>',
    save: '<path d="M5 3.5h11L20.5 8v11a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 19V5A1.5 1.5 0 0 1 5 3.5Z" ' + P + '/><path d="M8 3.5V9h8V3.5M7.5 20.5V14h9v6.5" ' + P + '/>',
    spark: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8" ' + P + '/>',
    timeline: '<circle cx="5" cy="6" r="1.6" ' + P + '/><circle cx="5" cy="18" r="1.6" ' + P + '/><circle cx="19" cy="12" r="1.6" ' + P + '/><path d="M5 7.6V16.4M6.5 6H15M6.5 18H15" ' + P + '/>',
  };

  function icon(name, cls) {
    var inner = ICONS[name] || ICONS.info;
    return '<svg class="ic ' + (cls || "") + '" viewBox="0 0 24 24" aria-hidden="true">' + inner + "</svg>";
  }

  window.QL = window.QL || {};
  window.QL.ICONS = ICONS;
  window.QL.icon = icon;
})();
