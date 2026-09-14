/* ─────────────────────────────────────────────────────────────
   Quetzalog application core — state, API, auth, router,
   shared widgets, global search palette, notifications.
   Page implementations live in pages-main.js / pages-extra.js.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";

  var API = "/api/v1";
  var TOKEN_KEY = "ql_token";
  var THEME_KEY = "ql_theme";

  var S = {
    token: localStorage.getItem(TOKEN_KEY) || "",
    user: null,
    range: "24h",
    riskType: "user",
    queue: { severity: "", status: "", owner: "", range: "", q: "", offset: 0 },
    ownerCache: [],
    ownersFetched: false,
    fieldsCache: null,
    searchPreset: "",
  };

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ═══ API ══════════════════════════════════════════════════ */
  function api(path, opts) {
    opts = opts || {};
    var headers = { "Content-Type": "application/json" };
    if (S.token) headers.Authorization = "Bearer " + S.token;
    return fetch(API + path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    }).then(function (r) {
      if (r.status === 401 && path.indexOf("/login") === -1) {
        logout(true);
        throw new Error("Session expired — sign in again");
      }
      return r.json().then(function (d) {
        if (d && d.status >= 400) throw new Error((d.errors && d.errors[0]) || d.message || "Request failed");
        return d && d.data != null ? d.data : d;
      });
    }).catch(function (e) {
      if (e instanceof TypeError) throw new Error("Cannot reach the Quetzalog API");
      throw e;
    });
  }

  /* ═══ Auth ═════════════════════════════════════════════════ */
  function showLogin() {
    $("#app-shell").hidden = true;
    $("#login-screen").hidden = false;
    document.body.classList.remove("logged-in");
    $("#login-dragon").innerHTML = QL.dragon({ size: 132, cls: "dragon-assemble" });
    setTimeout(function () { $("#login-user").focus(); }, 60);
  }

  function showApp() {
    $("#login-screen").hidden = true;
    $("#app-shell").hidden = false;
    document.body.classList.add("logged-in");
    renderUserChip();
    refreshNavBadge();
    refreshNotifs();
  }

  function currentRoute() {
    var m = (location.hash || "#/overview").match(/^#\/([a-z]+)/);
    return m ? m[1] : "";
  }

  function renderUserChip() {
    var u = S.user;
    if (!u) return;
    var name = u.username || "analyst";
    $("#user-avatar").textContent = name.slice(0, 2).toUpperCase();
    $("#user-name").textContent = name;
    $("#user-role").textContent = u.role || "";
    $("#sidebar-user").innerHTML =
       '<a class="nav-item' + (currentRoute() === "settings" ? " active" : "") + '" href="#/settings">' +
      QL.icon("user") + "<span>Settings</span></a>" +
      '<a class="nav-item" href="#" id="logout-btn">' + QL.icon("logout") + "<span>Sign out · " + QL.esc(name) + "</span></a>";
    var lb = $("#logout-btn");
    if (lb) lb.addEventListener("click", function (e) { e.preventDefault(); logout(false); });
  }

  function logout(silent) {
    S.token = "";
    S.user = null;
    localStorage.removeItem(TOKEN_KEY);
    if (!silent) api("/logout", { method: "POST" }).catch(function () {});
    showLogin();
  }

  function initLogin() {
    $("#login-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var username = $("#login-user").value.trim();
      var password = $("#login-pass").value;
      var err = $("#login-error");
      if (!username || !password) { err.textContent = "Username and password are required."; return; }
      err.textContent = "Signing in…";
      fetch(API + "/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, password: password }),
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.status >= 400) { err.textContent = d.message || "Invalid credentials"; return; }
        S.token = d.data.token;
        S.user = d.data.user;
        localStorage.setItem(TOKEN_KEY, S.token);
        err.textContent = "";
        showApp();
        if (location.hash) route();
        else location.hash = "#/overview";
      }).catch(function (e) {
        err.textContent = e instanceof TypeError ? "Cannot reach the server." : "Sign-in failed. Please try again.";
      });
    });
  }

  function tryAuth() {
    if (!S.token) { showLogin(); return; }
    api("/users/me").then(function (u) {
      S.user = u;
      showApp();
      if (location.hash) route();
      else location.hash = "#/overview";
    }).catch(function () {
      S.token = "";
      localStorage.removeItem(TOKEN_KEY);
      showLogin();
    });
  }

  /* ═══ Theme ════════════════════════════════════════════════ */
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem(THEME_KEY, t);
    $$("[data-theme-toggle]").forEach(function (b) {
      b.innerHTML = QL.icon(t === "dark" ? "moon" : "sun") +
        "<span>" + (t === "dark" ? "Light mode" : "Dark mode") + "</span>";
    });
  }
  function toggleTheme() {
    applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
    var p = $("#page");
    if (p && p.__rerender) p.__rerender();
  }

  /* ═══ Router ═══════════════════════════════════════════════ */
  var QLP = window.QLP = {};
  var PAGES = {
    overview: "overview",
    search: "search",
    builder: "builder",
    queue: "queue",
    finding: "finding",
    investigations: "investigations",
    investigation: "investigation",
    detections: "detections",
    risk: "risk",
    entities: "entities",
    entity: "entity",
    mitre: "mitre",
    settings: "settings",
  };

  function route() {
    var page = $("#page");
    page.innerHTML = QL.loading("Loading…");
    page.__rerender = null;
    var hash = location.hash || "#/overview";
    var m = hash.match(/^#\/([a-z]+)(?:\/([^/]+)(?:\/(.+?))?)?$/);
    var name = m && PAGES[m[1]] ? m[1] : "notfound";
    var arg = m ? m[2] : "";
    var arg2 = m ? m[3] : "";

    $$(".nav-item[data-route]").forEach(function (n) {
      n.classList.toggle("active",
        n.dataset.route === name ||
        (name === "finding" && n.dataset.route === "queue") ||
        (name === "investigation" && n.dataset.route === "investigations") ||
        (name === "entity" && n.dataset.route === "entities") ||
        (name === "builder" && n.dataset.route === "builder"));
    });
    document.body.classList.remove("nav-open");

    var fn = QLP[name] || QLP.notfound;
    Promise.resolve(fn(arg, arg2)).then(function (renderFn) {
      if (typeof renderFn === "function") page.__rerender = renderFn;
    }).catch(function (e) {
      page.innerHTML = QL.emptyState({
        icon: "warning",
        title: "Something went wrong",
        sub: e.message || String(e),
        action: '<button class="btn" id="retry-btn">' + QL.icon("refresh") + " Retry</button>",
      });
      var rb = $("#retry-btn");
      if (rb) rb.addEventListener("click", route);
    });
  }

  window.addEventListener("hashchange", route);

  /* ═══ Shared widgets ═══════════════════════════════════════ */
  function metricCard(icon, tint, value, label, sub, href, dataSev) {
    var open = href
      ? '<a class="metric-card" href="' + href + '"' + (dataSev ? ' data-sev="' + dataSev + '"' : "") + ">"
      : '<div class="metric-card">';
    var close = href ? "</a>" : "</div>";
    return open + '<div class="metric-icon" style="background:' + tint + '1f;color:' + tint + '">' +
      QL.icon(icon) + '</div><div class="metric-value">' + value + '</div>' +
      '<div class="metric-label">' + label + '</div>' +
      (sub ? '<div class="metric-sub">' + sub + "</div>" : "") + close;
  }

  function entityRow(type, value, score, findings) {
    var color = QL.riskColor(score);
    return '<div class="entity-row" data-entity="' + QL.esc(type) + "/" + QL.esc(value) + '">' +
      '<span class="entity-ic">' + QL.icon(QL.entityIcon(type)) + "</span>" +
      '<span class="entity-name"><span class="mono">' + QL.esc(value) + "</span></span>" +
      '<span class="entity-score" style="color:' + color + '">' + Math.round(Number(score) || 0) +
      (findings != null ? '<span class="faint small"> · ' + findings + " finding" + (findings === 1 ? "" : "s") + "</span>" : "") +
      "</span>" +
      '<span class="entity-bar"><i style="width:' + Math.min(100, Math.max(2, score)) + ";background:" + color + '"></i></span>' +
      "</div>";
  }

  function bindEntityRows(root) {
    $$(".entity-row", root).forEach(function (r) {
      r.addEventListener("click", function () {
        var parts = r.dataset.entity.split("/");
        location.hash = "#/entity/" + encodeURIComponent(parts[0]) + "/" + encodeURIComponent(parts[1]);
      });
    });
  }

  function pageHeader(title, sub, actions) {
    return '<div class="page-header"><div><h1>' + title + "</h1>" +
      (sub ? '<div class="page-sub">' + sub + "</div>" : "") +
      '</div><div class="page-actions">' + (actions || "") + "</div></div>";
  }

  function sel(id, aria, opts, current) {
    id = String(id || "").replace(/^#/, "");
    return '<select class="select" id="' + id + '" aria-label="' + aria + '">' +
      opts.map(function (o) {
        return '<option value="' + QL.esc(o[0]) + '"' + (o[0] === current ? " selected" : "") + ">" + o[1] + "</option>";
      }).join("") + "</select>";
  }

  function rangeMs(r) {
    return { "1h": 3600e3, "6h": 6 * 3600e3, "24h": 24 * 3600e3, "7d": 7 * 86400e3 }[r] || 24 * 3600e3;
  }

  function eventKv(e) {
    var rows = [
      ["Time", QL.fmtDateTime(e.timestamp) + " · " + QL.fmtAgo(e.timestamp), false],
      ["Severity", e.severity || "", false],
      ["Source", e.source || e.source_type || "", true],
      ["Host", e.host || "", true],
      ["User", e.user || "", false],
      ["Event type", e.event_type || "", false],
      ["Outcome", e.outcome || "", false],
      ["Source IP", e.source_ip || "", true],
      ["Dest IP", e.destination_ip || "", true],
      ["Process", e.process || "", true],
    ].filter(function (r) { return r[1]; });
    return '<dl class="tl-kv">' + rows.map(function (r) {
      return "<dt>" + r[0] + '</dt><dd class="' + (r[2] ? "mono" : "") + '">' + QL.esc(r[1]) + "</dd>";
    }).join("") + "</dl>" +
      (e.message ? '<div class="small" style="margin-top:8px;color:var(--ql-text-2)">' + QL.esc(e.message) + "</div>" : "") +
      (e.attributes && Object.keys(e.attributes).length ?
        '<details style="margin-top:8px"><summary class="small muted" style="cursor:pointer">Attributes (' +
        Object.keys(e.attributes).length + ")</summary>" +
        '<pre class="mono" style="font-size:11px;background:var(--ql-surface-2);border-radius:8px;padding:10px;overflow:auto;margin-top:8px">' +
        QL.esc(JSON.stringify(e.attributes, null, 2)) + "</pre></details>" : "");
  }

  function timelineHtml(events) {
    if (!events.length) return QL.emptyState({ icon: "activity", title: "No events", sub: "Nothing matched in this window." });
    var html = '<div class="timeline">';
    events.forEach(function (e) {
      var sev = QL.normSev(e.severity);
      var markIcon = sev === "critical" ? "warning" : sev === "high" ? "zap" : "activity";
      var title = e.message || e.event_type || "Event";
      html += '<div class="tl-item" data-ev>' +
        '<span class="tl-marker sev-' + sev + '">' + QL.icon(markIcon) + "</span>" +
        '<div class="tl-time">' + QL.fmtTimeSec(e.timestamp) + "</div>" +
        '<div class="tl-head"><span class="tl-title">' + QL.esc(title.slice(0, 140)) + "</span>" +
        (e.severity ? " " + QL.sevBadge(e.severity) : "") + "</div>" +
        '<div class="tl-meta">' +
        [e.user && "user " + e.user, e.host && "host " + e.host, e.source_ip && "from " + e.source_ip]
          .filter(Boolean).map(function (s) { return QL.esc(s); }).join(" · ") + "</div>" +
        '<div class="tl-detail">' + eventKv(e) + "</div></div>";
    });
    html += "</div>";
    return html;
  }

  function bindTimeline(root) {
    $$(".tl-head", root).forEach(function (h) {
      h.addEventListener("click", function () { h.closest(".tl-item").classList.toggle("open"); });
    });
  }

  function noteItem(author, body, ts) {
    return '<div style="padding:10px 0;border-bottom:1px solid var(--ql-border-soft)">' +
      '<div class="flex" style="justify-content:space-between"><span class="small" style="font-weight:650">' + QL.esc(author || "analyst") +
      '</span><span class="faint small">' + QL.fmtDateTime(ts) + "</span></div>" +
      '<div class="small" style="margin-top:4px;color:var(--ql-text-2);white-space:pre-wrap">' + QL.esc(body) + "</div></div>";
  }

  function entityGraphHtml(center, neighbors) {
    var W = 560, H = 300;
    var cx = W / 2, cy = H / 2;
    var n = neighbors.length || 1;
    var R = Math.min(110, 58 + n * 7);
    var nodes = [{ type: center.type, value: center.value, x: cx, y: cy, center: true }];
    neighbors.forEach(function (nb, i) {
      var ang = (i / Math.max(1, n)) * Math.PI * 2 - Math.PI / 2;
      nodes.push({ type: nb.type, value: nb.value, x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang), rel: nb.relation });
    });
    var edges = nodes.filter(function (nd) { return !nd.center; }).map(function (nd) {
      return '<line x1="' + cx + '" y1="' + cy + '" x2="' + nd.x + '" y2="' + nd.y +
        '" stroke="var(--ql-border)" stroke-width="1.5"/>' +
        (nd.rel ? '<text class="rel-edge-label" x="' + (cx + nd.x) / 2 + '" y="' + ((cy + nd.y) / 2 - 5) + '" text-anchor="middle">' +
        QL.esc(nd.rel) + "</text>" : "");
    }).join("");
    var blocks = nodes.map(function (nd) {
      var label = nd.value.length > 18 ? nd.value.slice(0, 17) + "…" : nd.value;
      var w = Math.max(92, label.length * 7.2 + 30);
      return '<g class="rel-node" style="cursor:pointer" data-entity="' + QL.esc(nd.type) + "/" + QL.esc(nd.value) + '">' +
        '<rect x="' + (nd.x - w / 2) + '" y="' + (nd.y - 24) + '" width="' + w + '" height="44" rx="10" ' +
        'fill="var(--ql-surface)" stroke="' + (nd.center ? "var(--ql-primary)" : "var(--ql-border)") + '" stroke-width="' + (nd.center ? 1.8 : 1) + '"/>' +
        '<text class="rel-node-label" x="' + nd.x + '" y="' + (nd.y - 3) + '" text-anchor="middle">' + QL.esc(label) + "</text>" +
        '<text class="rel-node-sub" x="' + nd.x + '" y="' + (nd.y + 13) + '" text-anchor="middle">' + QL.esc(nd.type) + "</text></g>";
    }).join("");
    return '<div class="rel-graph"><svg viewBox="0 0 ' + W + " " + H + '" width="' + W + '" height="' + H + '">' + edges + blocks + "</svg></div>";
  }

  function bindGraph(root) {
    $$(".rel-node", root).forEach(function (g) {
      g.addEventListener("click", function () {
        var parts = g.dataset.entity.split("/");
        location.hash = "#/entity/" + encodeURIComponent(parts[0]) + "/" + encodeURIComponent(parts[1]);
      });
    });
  }

  /* Finding / investigation actions shared by pages */
  function statusModal(current, onPick) {
    var opts = [["new", "New"], ["in_progress", "In progress"], ["investigating", "Investigating"],
      ["contained", "Contained"], ["resolved", "Resolved"], ["false_positive", "False positive"]];
    var close = QL.modal({
      title: "Change status",
      body: '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">' + opts.map(function (o) {
        return '<button class="btn" data-st="' + o[0] + '"' +
          (o[0] === current ? ' style="border-color:var(--ql-primary);color:var(--ql-primary)"' : "") + ">" + o[1] + "</button>";
      }).join("") + "</div>",
    });
    close.el.addEventListener("click", function (e) {
      var b = e.target.closest("[data-st]");
      if (!b) return;
      close();
      onPick(b.dataset.st);
    });
  }

  function createInvestigationModal(findingIds, fromFinding, presetTitle, presetSev) {
    var close = QL.modal({
      title: "Create Investigation",
      body:
        '<div class="field"><label for="inv-title">Title</label><input class="input" id="inv-title" value="' + QL.esc(presetTitle || "") + '"></div>' +
        '<div class="field"><label for="inv-desc">Description</label><textarea class="textarea" id="inv-desc" placeholder="What is the working theory?"></textarea></div>' +
        '<div class="grid" style="grid-template-columns:1fr 1fr">' +
        '<div class="field"><label for="inv-sev">Severity</label><select class="select" id="inv-sev">' +
        ["critical", "high", "medium", "low"].map(function (s) {
          return '<option value="' + s + '"' + (s === presetSev ? " selected" : "") + ">" + s + "</option>";
        }).join("") + "</select></div>" +
        '<div class="field"><label for="inv-assign">Assignee</label><input class="input" id="inv-assign" placeholder="' + QL.esc((S.user && S.user.username) || "") + '"></div>' +
        "</div>" +
        (findingIds.length ? '<div class="field-hint">' + findingIds.length + " finding" + (findingIds.length > 1 ? "s" : "") + " will be linked.</div>" : "") +
        (fromFinding ? "" : '<div class="field"><label for="inv-findings">Findings (comma-separated IDs, optional)</label><input class="input input-mono" id="inv-findings" placeholder="id1, id2"></div>'),
      footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>' + QL.icon("plus") + " Create</button>",
    });
    close.el.addEventListener("click", function (e) {
      if (e.target.dataset.x) close();
      if (e.target.dataset.ok) {
        var title = $("#inv-title").value.trim();
        if (!title) { QL.toast("Title is required", "error"); return; }
        var ids = findingIds.slice();
        var extra = $("#inv-findings");
        if (extra) ids = ids.concat(extra.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean));
        api("/investigations", {
          method: "POST",
          body: {
            title: title,
            description: $("#inv-desc").value.trim(),
            severity: $("#inv-sev").value,
            assignee: $("#inv-assign").value.trim(),
            finding_ids: ids,
          },
        }).then(function (inv) {
          close();
          QL.toast("Investigation created");
          location.hash = "#/investigation/" + inv.id;
        }).catch(function (er) { QL.toast(er.message, "error"); });
      }
    });
  }

  /* ═══ Nav badge ════════════════════════════════════════════ */
  function refreshNavBadge() {
    if ($("#app-shell").hidden) return;
    api("/findings?limit=1&status=new").catch(function () { return null; }).then(function (d) {
      var badge = $("#nav-queue-badge");
      if (!badge) return;
      var total = d && d.total;
      if (total) { badge.hidden = false; badge.textContent = total > 99 ? "99+" : total; }
      else badge.hidden = true;
    });
  }

  /* ═══ Global search palette (⌘K) ═══════════════════════════ */
  function initPalette() {
    var kmod = $("#kbd-mod");
    if (kmod) kmod.textContent = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "") ? "⌘" : "Ctrl";

    function open() {
      if ($("#app-shell").hidden) return;
      var close = QL.modal({
        titleHtml: '<div class="search-box" style="max-width:440px"><span class="ic-lead">' + QL.icon("search") + "</span>" +
          '<input class="input input-mono" id="pal-input" placeholder="Search findings, investigations, events…" style="padding-right:52px"></div>' +
          '<span class="kbd" aria-hidden="true">' + (kmod ? kmod.textContent : "⌘") + "K</span>",
        body: '<div id="pal-results" style="min-height:60px"></div>',
      });
      var input = $("#pal-input");
      var box = $("#pal-results");
      var t;
      input.addEventListener("input", function () {
        clearTimeout(t);
        t = setTimeout(search, 220);
      });
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          var first = box.querySelector("[data-go]");
          if (first) first.click();
        }
      });
      box.innerHTML = '<div class="small muted" style="padding:8px 4px">Type to search. Findings, investigations and raw events are searched.</div>';

      function search() {
        var v = input.value.trim();
        if (!v) { box.innerHTML = '<div class="small muted" style="padding:8px 4px">Type to search.</div>'; return; }
        box.innerHTML = QL.loading("Searching…");
        Promise.all([
          api("/findings?q=" + encodeURIComponent(v) + "&limit=5").catch(function () { return { findings: [] }; }),
          api("/investigations?limit=50").catch(function () { return { investigations: [] }; }),
          api("/search", { method: "POST", body: { query: v, limit: 5 } }).catch(function () { return { results: [] }; }),
        ]).then(function (res) {
          var f = res[0].findings || [];
          var invs = (res[1].investigations || []).filter(function (i) {
            return (i.title + " " + (i.description || "")).toLowerCase().indexOf(v.toLowerCase()) > -1;
          }).slice(0, 4);
          var evs = res[2].results || [];
          var html = "";
          if (f.length) {
            html += '<div class="small faint" style="padding:6px 8px 4px;font-weight:700;letter-spacing:.05em">FINDINGS</div>' +
              f.map(function (x) {
                return '<button class="menu-item" data-go="#/finding/' + x.id + '">' + QL.sevBadge(x.severity) +
                  '<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + QL.esc(x.title) + "</span></button>";
              }).join("");
          }
          if (invs.length) {
            html += '<div class="small faint" style="padding:6px 8px 4px;font-weight:700;letter-spacing:.05em">INVESTIGATIONS</div>' +
              invs.map(function (x) {
                return '<button class="menu-item" data-go="#/investigation/' + x.id + '">' + QL.statusBadge(x.status) +
                  '<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + QL.esc(x.title) + "</span></button>";
              }).join("");
          }
          if (evs.length) {
            html += '<div class="small faint" style="padding:6px 8px 4px;font-weight:700;letter-spacing:.05em">EVENTS</div>' +
              evs.map(function (x) {
                return '<button class="menu-item" data-go="#/search?q=' + encodeURIComponent(v) + '">' +
                  (x.severity ? QL.sevBadge(x.severity) : '<span class="faint small">event</span>') +
                  '<span class="small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
                  QL.esc((x.message || x.host || x.source || "event").slice(0, 80)) + "</span></button>";
              }).join("");
          }
          box.innerHTML = html || '<div class="small muted" style="padding:8px 4px">No matches for "' + QL.esc(v) + '".</div>';
          $$(".pal-go, [data-go]", box).forEach(function (b) {
            b.addEventListener("click", function () {
              var dest = b.dataset.go;
              if (dest.indexOf("#/search") === 0) S.searchPreset = decodeURIComponent(dest.replace("#/search?q=", ""));
              close();
              location.hash = dest;
            });
          });
        });
      }
    }

    $("#global-search-btn").addEventListener("click", open);
    document.addEventListener("keydown", function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName || "");
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        open();
      } else if (!typing && !e.metaKey && !e.ctrlKey && !e.altKey && e.key === "b") {
        location.hash = "#/builder";
      }
    });
  }

  /* ═══ Notifications ════════════════════════════════════════ */
  function refreshNotifs() {
    if ($("#app-shell").hidden) return;
    api("/alerts?limit=10").then(function (alerts) {
      var list = (alerts || []).filter(function (a) { return a.status === "new"; });
      var count = $("#notif-count");
      if (list.length) {
        count.hidden = false;
        count.textContent = list.length;
      } else count.hidden = true;
      var menu = $("#notif-menu");
      if (!list.length) {
        menu.innerHTML = '<div class="small muted" style="padding:14px 10px">No new alerts.</div>';
        return;
      }
      menu.innerHTML = list.map(function (a) {
        return '<div class="notif-item" data-a="' + a.id + '">' +
          '<div class="notif-title">' + QL.sevBadge(a.severity) + " " + QL.esc(a.title || "Alert") + "</div>" +
          '<div class="notif-sub">' + (a.description ? QL.esc(a.description.slice(0, 90)) : "") + " · " + QL.fmtAgo(a.timestamp) + "</div></div>";
      }).join("");
      $$(".notif-item", menu).forEach(function (n) {
        n.addEventListener("click", function () {
          api("/alerts/" + n.dataset.a + "/acknowledge", { method: "POST" }).then(function () {
            QL.toast("Alert acknowledged");
            menu.hidden = true;
            refreshNotifs();
          }).catch(function (e) { QL.toast(e.message, "error"); });
        });
      });
    }).catch(function () {});
  }

  function initTopbar() {
    $("#notif-btn").addEventListener("click", function (e) {
      e.stopPropagation();
      var menu = $("#notif-menu");
      var userMenu = $("#user-menu");
      userMenu.hidden = true;
      menu.hidden = !menu.hidden;
    });
    $("#user-chip").addEventListener("click", function (e) {
      e.stopPropagation();
      var userMenu = $("#user-menu");
      var menu = $("#notif-menu");
      menu.hidden = true;
      if (!userMenu.hidden) { userMenu.hidden = true; return; }
      userMenu.innerHTML =
        '<div style="padding:8px 10px" class="flex-between">' +
        '<div><b class="small">' + QL.esc(S.user ? S.user.username : "") + "</b>" +
        '<div class="faint small">' + QL.esc((S.user && S.user.role) || "") + "</div></div>" +
        '<span class="avatar">' + QL.esc((S.user && S.user.username || "?").slice(0, 2).toUpperCase()) + "</span></div>" +
        '<div class="menu-sep"></div>' +
        '<button class="menu-item" data-a="theme">' + QL.icon("sun") + " Toggle theme</button>" +
        '<a class="menu-item" href="#/settings">' + QL.icon("settings") + " Settings</a>" +
        '<button class="menu-item danger" data-a="logout">' + QL.icon("logout") + " Sign out</button>";
      userMenu.hidden = false;
      userMenu.addEventListener("click", onUserMenu, { once: false });
    });
    function onUserMenu(e) {
      var b = e.target.closest("[data-a]");
      if (!b) return;
      $("#user-menu").hidden = true;
      if (b.dataset.a === "theme") toggleTheme();
      if (b.dataset.a === "logout") logout(false);
    }
    $("#help-btn").addEventListener("click", function () {
      QL.modal({
        title: "Quetzalog — keyboard & concepts",
        body:
          '<div style="display:flex;flex-direction:column;gap:10px" class="small">' +
          '<div class="flex-between"><span>Global search</span><span class="kbd">⌘ K</span></div>' +
          '<div class="flex-between"><span>Jump to SPL Builder</span><span class="kbd">b</span></div>' +
          '<div class="flex-between"><span>Close dialog</span><span class="kbd">esc</span></div>' +
          '<div style="border-top:1px solid var(--ql-border-soft);padding-top:10px;color:var(--ql-text-muted)">Workflow: Logs → Search → SPL → Detection → Finding → Risk → Investigation → Evidence → Response. Severity is always shown as color <i>plus</i> label.</div></div>',
      });
    });
    document.addEventListener("click", function () {
      $("#notif-menu").hidden = true;
      $("#user-menu").hidden = true;
    });
    $("#notif-menu").addEventListener("click", function (e) { e.stopPropagation(); });
    $("#user-menu").addEventListener("click", function (e) { e.stopPropagation(); });

    /* mobile nav */
    $("#hamburger").addEventListener("click", function () {
      document.body.classList.toggle("nav-open");
    });
    $("#nav-scrim").addEventListener("click", function () {
      document.body.classList.remove("nav-open");
    });
  }

  function initIcons() {
    $$("[data-icon]").forEach(function (el) {
      el.innerHTML = QL.icon(el.dataset.icon);
      el.classList.add("ic-holder");
    });
    /* sidebar brand */
    $("#brand-slot").innerHTML = QL.logo({ tagline: true });
    applyTheme(localStorage.getItem(THEME_KEY) || "dark");
  }

  function init() {
    initIcons();
    initLogin();
    initTopbar();
    initPalette();
    tryAuth();
  }

  window.QL = window.QL || {};
  Object.assign(window.QL, {
    state: S,
    api: api,
    logout: logout,
    toggleTheme: toggleTheme,
    applyTheme: applyTheme,
    route: route,
    pageHeader: pageHeader,
    metricCard: metricCard,
    entityRow: entityRow,
    bindEntityRows: bindEntityRows,
    sel: sel,
    rangeMs: rangeMs,
    eventKv: eventKv,
    timelineHtml: timelineHtml,
    bindTimeline: bindTimeline,
    noteItem: noteItem,
    entityGraphHtml: entityGraphHtml,
    bindGraph: bindGraph,
    statusModal: statusModal,
    createInvestigationModal: createInvestigationModal,
    refreshNotifs: refreshNotifs,
  });

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
