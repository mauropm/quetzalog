/* ─────────────────────────────────────────────────────────────
   Quetzalog UI helpers — DOM, toasts, modals, badges, formatting
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function el(html) {
    var t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstElementChild;
  }

  /* ── toasts ── */
  function toast(msg, type, ms) {
    var region = document.querySelector(".toast-region");
    if (!region) {
      region = el('<div class="toast-region" aria-live="polite"></div>');
      document.body.appendChild(region);
    }
    var icon = type === "error" ? "warning" : "check";
    var t = el('<div class="toast ' + (type || "") + '" role="status">' +
      QL.icon(icon) + "<span>" + esc(msg) + "</span></div>");
    region.appendChild(t);
    setTimeout(function () {
      t.classList.add("out");
      setTimeout(function () { t.remove(); }, 260);
    }, ms || 3200);
  }

  /* ── modal ── */
  function modal(opts) {
    var scrim = el(
      '<div class="modal-scrim" role="dialog" aria-modal="true" aria-label="' + esc(opts.title || "Dialog") + '">' +
      '<div class="modal' + (opts.large ? " modal-lg" : "") + '">' +
      '<div class="modal-header"><div class="modal-title">' + (opts.titleHtml || esc(opts.title || "")) +
      '</div><button class="icon-btn modal-x" aria-label="Close">' + QL.icon("x") + "</button></div>" +
      (opts.body ? '<div class="modal-body">' + opts.body + "</div>" : "") +
      (opts.footer ? '<div class="modal-footer">' + opts.footer + "</div>" : "") +
      "</div></div>"
    );
    document.body.appendChild(scrim);
    var close = function () {
      scrim.remove();
      document.removeEventListener("keydown", onKey);
    };
    var onKey = function (e) { if (e.key === "Escape") close(); };
    document.addEventListener("keydown", onKey);
    scrim.addEventListener("click", function (e) { if (e.target === scrim) close(); });
    var x = scrim.querySelector(".modal-x");
    if (x) x.addEventListener("click", close);
    var first = scrim.querySelector("input, select, button:not(.modal-x)");
    if (first) setTimeout(function () { first.focus(); }, 30);
    close.el = scrim;
    return close;
  }

  function confirmDialog(title, message, opts) {
    opts = opts || {};
    var close = modal({
      title: title,
      body: '<p class="small muted" style="margin:0">' + esc(message) + "</p>",
      footer:
        '<button class="btn" data-act="cancel">Cancel</button>' +
        '<button class="btn ' + (opts.danger ? "btn-danger" : "btn-primary") + '" data-act="ok">' + esc(opts.okLabel || "Confirm") + "</button>",
    });
    close.el.addEventListener("click", function (e) {
      var b = e.target.closest("[data-act]");
      if (!b) return;
      if (b.dataset.act === "ok") { close(); if (opts.onOk) opts.onOk(); }
      else close();
    });
    return close;
  }

  /* ── severity / status / risk ── */
  function normSev(raw) {
    var s = String(raw || "").toLowerCase();
    if (s === "critical" || s === "emergency" || s === "alert") return "critical";
    if (s === "high" || s === "err" || s === "error") return "high";
    if (s === "medium" || s === "warning" || s === "warn" || s === "notice") return "medium";
    if (s === "low" || s === "info") return "low";
    if (s === "debug") return "debug";
    return "medium";
  }

  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", debug: "Debug" };
  var SEV_COLOR = {
    critical: "var(--ql-sev-critical)", high: "var(--ql-sev-high)", medium: "var(--ql-sev-medium)",
    low: "var(--ql-sev-low)", info: "var(--ql-sev-info)", debug: "var(--ql-text-faint)",
    success: "var(--ql-sev-success)",
  };

  function sevBadge(raw, labelOverride) {
    var s = normSev(raw);
    var cls = s === "debug" ? "muted" : s;
    return '<span class="badge badge-sev ' + cls + '"><span class="dot" aria-hidden="true"></span>' +
      esc(labelOverride || SEV_LABEL[s] || s) + "</span>";
  }

  function sevColor(raw) { return SEV_COLOR[normSev(raw)] || SEV_COLOR.info; }

  var STATUS_LABEL = {
    new: "New", in_progress: "In progress", investigating: "Investigating",
    contained: "Contained", resolved: "Resolved", false_positive: "False positive", cancelled: "Cancelled",
  };
  function statusBadge(status) {
    var s = String(status || "new");
    return '<span class="badge badge-status ' + s + '">' + esc(STATUS_LABEL[s] || s) + "</span>";
  }

  function riskLevel(score) {
    if (score >= 80) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    if (score > 0) return "low";
    return "none";
  }
  function riskColor(score) {
    var lv = riskLevel(score);
    return lv === "none" ? "var(--ql-text-muted)" : SEV_COLOR[lv];
  }
  function riskBadge(score, showLabel) {
    var n = Math.round(Number(score) || 0);
    return '<span class="risk-badge"><span class="lbl">' + (showLabel === false ? "" : "risk") + "</span>" +
      '<span class="' + riskLevel(n) + '">' + n + "</span></span>";
  }
  function riskBar(score, w) {
    var n = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
    return '<span class="risk-bar" style="width:' + (w || 64) + 'px" role="img" aria-label="Risk ' + n + ' of 100">' +
      '<i style="width:' + n + "%;background:" + riskColor(n) + '"></i></span>';
  }

  /* ── formatting ── */
  function fmtNum(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, "") + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
    if (n >= 10000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "K";
    return n.toLocaleString();
  }

  function pad(n) { return n < 10 ? "0" + n : "" + n; }

  function fmtTime(ts) {
    var d = new Date(ts);
    if (isNaN(d)) return "";
    return pad(d.getHours()) + ":" + pad(d.getMinutes());
  }
  function fmtTimeSec(ts) {
    var d = new Date(ts);
    if (isNaN(d)) return "";
    return fmtTime(ts) + ":" + pad(d.getSeconds());
  }
  function fmtDate(ts) {
    var d = new Date(ts);
    if (isNaN(d)) return "";
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
  }
  function fmtDateTime(ts) {
    var d = new Date(ts);
    if (isNaN(d)) return "";
    return fmtDate(ts) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }
  function fmtAgo(ts) {
    var d = new Date(ts).getTime();
    if (isNaN(d)) return "";
    var s = Math.max(0, (Date.now() - d) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  /* ── entity icons ── */
  var ENTITY_ICON = {
    user: "user", host: "host", ip: "ip", source_ip: "ip", destination_ip: "ip",
    process: "process", file: "file", domain: "domain", email: "user",
    session: "link", trace_id: "link",
  };
  function entityIcon(type) { return ENTITY_ICON[String(type || "").toLowerCase()] || "entities"; }

  /* ── empty / loading blocks ── */
  function emptyState(opts) {
    opts = opts || {};
    var top = opts.dragon
      ? '<div class="dragon-slot" aria-hidden="true">' + QL.dragon({ size: opts.dragonSize || 72, cls: "dragon-assemble" }) + "</div>"
      : '<div class="dragon-slot" aria-hidden="true" style="color:var(--ql-text-faint)">' + QL.icon(opts.icon || "info", "empty-ic") + "</div>";
    var action = opts.action
      ? '<div class="empty-actions">' + opts.action + "</div>"
      : "";
    return '<div class="empty">' + top +
      (opts.title ? "<h3>" + esc(opts.title) + "</h3>" : "") +
      (opts.sub ? "<p>" + opts.sub + "</p>" : "") +
      action + "</div>";
  }

  function loading(label) {
    return '<div class="loading"><div class="spinner" aria-label="Loading"></div><span>' +
      esc(label || "Loading…") + "</span></div>";
  }

  function kv(icon, label, value, mono) {
    return '<div class="kv"><div class="kv-label">' + (icon ? QL.icon(icon) : "") + esc(label) +
      '</div><div class="kv-value' + (mono ? " mono" : "") + '">' + (value == null || value === "" ?
        '<span class="faint">—</span>' : esc(value)) + "</div></div>";
  }

  /* ── misc ── */
  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments, ctx = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
  }

  function download(filename, text) {
    var a = el('<a download="' + esc(filename) + '"></a>');
    a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(text);
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  window.QL = window.QL || {};
  Object.assign(window.QL, {
    esc, el, toast, modal, confirmDialog,
    normSev, sevBadge, sevColor, statusBadge,
    riskLevel, riskColor, riskBadge, riskBar,
    fmtNum, fmtTime, fmtTimeSec, fmtDate, fmtDateTime, fmtAgo,
    entityIcon, emptyState, loading, kv, debounce, download,
  });
})();
