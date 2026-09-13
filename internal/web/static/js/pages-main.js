/* ─────────────────────────────────────────────────────────────
   Quetzalog pages (main) — Overview, Analyst Queue, Finding,
   Investigations.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";
  var QL_ = window.QL;
  var api = QL_.api;
  var S = QL_.state;
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ═══ Overview ═════════════════════════════════════════════ */
  window.QLP.overview = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Security Overview", "Real-time visibility into your environment",
      '<span class="range-group" id="range-group" role="tablist" aria-label="Time range"></span>') +
      '<div id="ov-body">' + QL.loading("Scanning the environment…") + "</div>";

    load();

    function load() {
      api("/soc/overview?range=" + S.range).then(function (d) {
        var posture = d.findings.posture || {};
        var ev = d.events || {};
        var top = d.top_entities || {};

        page.innerHTML = QL_.pageHeader("Security Overview", "Real-time visibility into your environment",
          '<span class="range-group" id="range-group"></span>') +
          '<div class="metrics-row">' +
          QL_.metricCard("shieldAlert", "var(--ql-sev-critical)", QL.fmtNum(posture.critical || 0), "Critical Findings", "in queue") +
          QL_.metricCard("warning", "var(--ql-sev-high)", QL.fmtNum(posture.high || 0), "High Findings", "in queue") +
          QL_.metricCard("queue", "var(--ql-accent)", QL.fmtNum(posture.open || 0), "Open Findings", "all severities") +
          QL_.metricCard("activity", "var(--ql-secondary)", QL.fmtNum(ev.total || 0), "Events · " + S.range, (ev.eps || 0) + " events/sec") +
          "</div>" +
          '<div class="dash-grid">' +
          '<div class="card"><div class="card-header"><div><div class="card-title">' + QL.icon("activity") +
            " Security Activity</div><div class='card-sub'>Detections and high-risk activity</div></div></div>" +
          '<div class="card-body"><canvas id="cv-activity" class="chart-canvas"></canvas>' +
          '<div class="flex small" style="gap:14px;margin-top:8px;color:var(--ql-text-muted);flex-wrap:wrap">' +
          '<span class="flex" style="gap:5px"><i style="width:10px;height:10px;border-radius:3px;background:var(--ql-secondary);display:inline-block;opacity:.7"></i>Events</span>' +
          '<span class="flex" style="gap:5px"><i style="width:10px;height:10px;border-radius:3px;background:var(--ql-sev-critical);display:inline-block"></i>Critical</span>' +
          '<span class="flex" style="gap:5px"><i style="width:10px;height:10px;border-radius:3px;background:var(--ql-sev-high);display:inline-block"></i>High</span>' +
          '<span class="flex" style="gap:5px"><i style="width:10px;height:10px;border-radius:3px;background:var(--ql-sev-medium);display:inline-block"></i>Medium</span>' +
          '<span class="flex" style="gap:5px"><i style="width:10px;height:10px;border-radius:3px;background:var(--ql-sev-low);display:inline-block"></i>Low</span></div></div></div>' +
          '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("gauge") +
            " Top Risky Entities</div>" +
            '<span class="range-group" id="entity-tabs">' +
            ["user", "host"].map(function (t) {
              return '<button class="range-pill' + (t === "user" ? " active" : "") + '" data-et="' + t + '">' + t + "s</button>";
            }).join("") + "</span></div>" +
            '<div class="card-body" id="entity-rows" style="padding-top:4px"></div></div></div>' +
          "</div>" +
          '<div class="dash-grid">' +
          '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("filter") +
            " Findings by Severity</div></div><div class='card-body'>" +
          '<canvas id="cv-sev" class="chart-canvas sm"></canvas></div></div>' +
          '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("globe") +
            " Most Active Sources</div></div><div class='card-body'>" +
          '<canvas id="cv-sources" class="chart-canvas sm"></canvas></div></div>' +
          '<div class="card span-2"><div class="card-header"><div class="card-title">' + QL.icon("queue") +
            " Latest Findings</div><a class='small flex' href='#/queue' style='color:var(--ql-text-muted)'>Open queue " + QL.icon("chevron-right") + "</a></div>" +
          '<div class="card-body card-flush" id="ov-findings"></div></div>' +
          "</div>";

        renderRangeGroup($("#range-group"));
        loadEntities("user", top);
        $$("#entity-tabs .range-pill").forEach(function (b) {
          b.addEventListener("click", function () {
            $$("#entity-tabs .range-pill").forEach(function (x) { x.classList.remove("active"); });
            b.classList.add("active");
            loadEntities(b.dataset.et, top);
          });
        });

        QL.charts.activity($("#cv-activity"), ev.timeline || [], d.findings.timeline || [], {});
        QL.charts.severityBars($("#cv-sev"), [
          { label: "Critical", value: posture.critical || 0, color: "var(--ql-sev-critical)" },
          { label: "High", value: posture.high || 0, color: "var(--ql-sev-high)" },
          { label: "Medium", value: posture.medium || 0, color: "var(--ql-sev-medium)" },
          { label: "Low", value: posture.low || 0, color: "var(--ql-sev-low)" },
        ]);
        QL.charts.hbars($("#cv-sources"), (top.active_source_ips || []).map(function (s) {
          return { label: s.value, value: s.count, color: "var(--ql-feather-cyan)" };
        }));

        api("/findings?limit=6&sort_by=last_seen&sort_order=desc").then(function (f) {
          var el = $("#ov-findings");
          if (!el) return;
          var list = f.findings || [];
          if (!list.length) {
            el.innerHTML = QL.emptyState({ icon: "queue", title: "Queue is clear", sub: "No findings need attention right now." });
            return;
          }
          el.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
            "<th>Severity</th><th>Finding</th><th>User</th><th>Host</th><th>Last Seen</th></tr></thead><tbody>" +
            list.map(function (fd) {
              return '<tr class="row-sev ' + QL.normSev(fd.severity) + '" data-f="' + fd.id + '">' +
                "<td>" + QL.sevBadge(fd.severity) + "</td>" +
                '<td class="cell-title">' + QL.esc(fd.title) + "</td>" +
                "<td>" + QL.esc(fd.user || "—") + "</td>" +
                "<td>" + QL.esc(fd.host || "—") + "</td>" +
                '<td class="cell-muted">' + QL.fmtAgo(fd.last_seen) + "</td></tr>";
            }).join("") + "</tbody></table></div>";
          $$("#ov-findings tr[data-f]").forEach(function (tr) {
            tr.classList.add("clickable");
            tr.addEventListener("click", function () { location.hash = "#/finding/" + tr.dataset.f; });
          });
        }).catch(function () {});
      }).catch(function (e) {
        $("#ov-body").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load overview", sub: e.message });
      });
    }

    function loadEntities(type, top) {
      var el = $("#entity-rows");
      if (!el) return;
      var list = type === "user" ? (top.risky_users || []) : (top.risky_hosts || []);
      if (!list.length) {
        el.innerHTML = QL.emptyState({ icon: "gauge", title: "No risk yet", sub: "Risk builds as findings open." });
        return;
      }
      el.innerHTML = '<div class="entity-list">' + list.map(function (e) {
        return QL_.entityRow(e.type, e.value, e.risk_score, e.findings);
      }).join("") + "</div>";
      QL_.bindEntityRows(el);
    }

    function renderRangeGroup(group) {
      if (!group) return;
      ["15m", "1h", "6h", "24h", "7d"].forEach(function (r) {
        var b = QL.el('<button class="range-pill' + (r === S.range ? " active" : "") + '" role="tab">' + r + "</button>");
        b.addEventListener("click", function () {
          $$(".range-pill", group).forEach(function (x) { x.classList.remove("active"); });
          b.classList.add("active");
          S.range = r;
          load();
        });
        group.appendChild(b);
      });
    }
  };

  /* ═══ Analyst Queue ════════════════════════════════════════ */
  window.QLP.queue = function () {
    var page = $("#page");
    var f = S.queue;

    page.innerHTML = QL_.pageHeader("Analyst Queue", "Findings that require your attention",
      '<button class="btn btn-primary" id="q-new-inv">' + QL.icon("plus") + " Investigate</button>") +
      '<div class="card" style="margin-bottom:14px"><div class="card-body" style="padding:12px">' +
      '<div class="filter-bar" style="margin-bottom:10px">' +
      QL_.sel("#q-sev", "Severity", [["", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]], f.severity) +
      QL_.sel("#q-status", "Status", [["", "All statuses"], ["new", "New"], ["in_progress", "In progress"], ["investigating", "Investigating"], ["contained", "Contained"], ["resolved", "Resolved"], ["false_positive", "False positive"]], f.status) +
      '<select class="select" id="q-owner" aria-label="Owner"><option value="">All owners</option></select>' +
      QL_.sel("#q-range", "Time", [["", "All time"], ["1h", "Last hour"], ["6h", "Last 6 hours"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"]], f.range) +
      (hasFilters() ? '<button class="filter-chip" id="q-clear">' + QL.icon("x") + " Clear</button>" : "") +
      "</div>" +
      '<div class="search-box" style="max-width:480px"><span class="ic-lead">' + QL.icon("search") + "</span>" +
      '<input class="input" id="q-search" placeholder="Search findings…" value="' + QL.esc(f.q) + '"></div>' +
      "</div></div>" +
      '<div class="card card-flush" id="q-table">' + QL.loading("Loading queue…") + "</div>";

    fillOwners();
    load();

    function hasFilters() { return !!(f.severity || f.status || f.owner || f.range || f.q); }

    function fillOwners() {
      if (!S.ownerCache.length) {
        api("/findings?limit=100").then(function (d) {
          var seen = {};
          (d.findings || []).forEach(function (x) { if (x.owner) seen[x.owner] = 1; });
          S.ownerCache = Object.keys(seen).sort();
          fillOwners();
        }).catch(function () {});
      } else {
        var o = $("#q-owner");
        if (!o) return;
        S.ownerCache.forEach(function (u) {
          o.insertAdjacentHTML("beforeend", '<option value="' + QL.esc(u) + '"' + (u === f.owner ? " selected" : "") + ">" + QL.esc(u) + "</option>");
        });
      }
    }

    function load() {
      var q = new URLSearchParams();
      if (f.severity) q.set("severity", f.severity);
      if (f.status) q.set("status", f.status);
      if (f.owner) q.set("owner", f.owner);
      if (f.range) q.set("start", new Date(Date.now() - QL_.rangeMs(f.range)).toISOString());
      if (f.q) q.set("q", f.q);
      q.set("limit", "50");
      q.set("offset", String(f.offset));
      q.set("sort_by", "last_seen");
      q.set("sort_order", "desc");

      api("/findings?" + q).then(function (d) {
        var list = d.findings || [];
        var total = d.total || 0;
        var el = $("#q-table");
        if (!list.length) {
          el.innerHTML = hasFilters()
            ? QL.emptyState({ icon: "queue", title: "No findings match", sub: "Try adjusting the filters." })
            : QL.emptyState({
                dragon: true,
                title: "Nothing suspicious here.",
                sub: "Your dragon checked the logs and didn't find anything interesting.",
                action: '<a class="btn" href="#/search">' + QL.icon("search") + " Explore Search</a>",
              });
          return;
        }
        el.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Severity</th><th>Title</th><th>Risk</th><th>User</th><th>Host</th><th>First Seen</th><th>Status</th><th>Owner</th>" +
          "</tr></thead><tbody>" +
          list.map(function (fd) {
            return '<tr class="row-sev ' + QL.normSev(fd.severity) + '" data-f="' + fd.id + '">' +
              "<td>" + QL.sevBadge(fd.severity) + "</td>" +
              '<td class="cell-title">' + QL.esc(fd.title) +
              (fd.mitre_technique ? '<div class="cell-muted">' + QL.esc(fd.mitre_tactic || "") + " " + QL.esc(fd.mitre_technique) + "</div>" : "") +
              "</td>" +
              "<td>" + QL.riskBadge(fd.risk_score, false) + "</td>" +
              "<td>" + QL.esc(fd.user || "—") + "</td>" +
              "<td>" + QL.esc(fd.host || "—") + "</td>" +
              '<td class="cell-muted nowrap">' + QL.fmtTime(fd.first_seen) + " · " + QL.fmtAgo(fd.first_seen) + "</td>" +
              "<td>" + QL.statusBadge(fd.status) + "</td>" +
              '<td class="cell-muted">' + (fd.owner
                ? '<span class="avatar" style="width:20px;height:20px;font-size:9px;display:inline-flex">' + QL.esc(fd.owner.slice(0, 2).toUpperCase()) + "</span>"
                : "—") + "</td></tr>";
          }).join("") + "</tbody></table></div>" +
          '<div class="pager"><span class="pager-info">' + (f.offset + 1) + "–" + Math.min(f.offset + 50, total) + " of " + total +
          '</span><span class="pager-btns">' +
          '<button class="btn btn-sm" id="q-prev"' + (f.offset === 0 ? " disabled" : "") + ">" + QL.icon("chevron-left") + " Prev</button>" +
          '<button class="btn btn-sm" id="q-next"' + (f.offset + 50 >= total ? " disabled" : "") + ">Next " + QL.icon("chevron-right") + "</button></span></div>";

        $$("#q-table tr[data-f]").forEach(function (tr) {
          tr.classList.add("clickable");
          tr.addEventListener("click", function () { location.hash = "#/finding/" + tr.dataset.f; });
        });
        var prev = $("#q-prev"), next = $("#q-next");
        if (prev) prev.addEventListener("click", function () { f.offset -= 50; load(); });
        if (next) next.addEventListener("click", function () { f.offset += 50; load(); });
      }).catch(function (e) {
        $("#q-table").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load queue", sub: e.message });
      });
    }

    $("#q-sev").addEventListener("change", function (e) { f.severity = e.target.value; f.offset = 0; load(); });
    $("#q-status").addEventListener("change", function (e) { f.status = e.target.value; f.offset = 0; load(); });
    $("#q-owner").addEventListener("change", function (e) { f.owner = e.target.value; f.offset = 0; load(); });
    $("#q-range").addEventListener("change", function (e) { f.range = e.target.value; f.offset = 0; load(); });
    $("#q-search").addEventListener("input", QL.debounce(function (e) { f.q = e.target.value.trim(); f.offset = 0; load(); }, 300));
    var clear = $("#q-clear");
    if (clear) clear.addEventListener("click", function () {
      f.severity = f.status = f.owner = f.range = f.q = "";
      f.offset = 0;
      QL_.route();
    });
    $("#q-new-inv").addEventListener("click", function () {
      QL_.createInvestigationModal([], false);
    });
  };

  /* ═══ Finding detail ═══════════════════════════════════════ */
  window.QLP.finding = function (id) {
    var page = $("#page");
    api("/findings/" + encodeURIComponent(id)).then(function (f) {
      page.innerHTML =
        '<div class="flex" style="margin-bottom:12px"><a class="btn btn-ghost btn-sm" href="#/queue">' + QL.icon("arrow-left") + " Back to queue</a></div>" +
        '<div class="page-header"><div style="min-width:0">' +
        '<div class="flex" style="gap:8px;flex-wrap:wrap;margin-bottom:8px">' + QL.sevBadge(f.severity) +
        " " + QL.statusBadge(f.status) + " " + QL.riskBadge(f.risk_score) +
        (f.mitre_technique ? mitreChip(f.mitre_tactic, f.mitre_technique) : "") + "</div>" +
        '<h1 style="font-size:24px">' + QL.esc(f.title) + "</h1>" +
        (f.description ? '<div class="page-sub" style="max-width:760px;margin-top:6px">' + QL.esc(f.description) + "</div>" : "") +
        "</div><div class='page-actions'>" +
        '<button class="btn" id="f-assign">' + QL.icon("user") + " Assign</button>" +
        '<button class="btn" id="f-status">' + QL.icon("clock") + " Change Status</button>" +
        '<button class="btn btn-primary" id="f-investigate">' + QL.icon("investigate") + " Investigate</button>" +
        "</div></div>" +
        '<div class="card" style="margin-bottom:14px"><div class="card-body"><div class="kv-grid">' +
        QL.kv("user", "User", f.user) +
        QL.kv("host", "Host", f.host) +
        QL.kv("ip", "Source", f.source_ip, true) +
        QL.kv("ip", "Destination", f.destination_ip, true) +
        QL.kv("crosshair", "MITRE", f.mitre_tactic ? f.mitre_tactic + " · " + f.mitre_technique : f.mitre_technique, true) +
        QL.kv("clock", "First Seen", f.first_seen ? QL.fmtDateTime(f.first_seen) : "") +
        QL.kv("clock", "Last Seen", f.last_seen ? QL.fmtDateTime(f.last_seen) : "") +
        QL.kv("shieldAlert", "Detection", f.detection_name || f.detection_id, true) +
        QL.kv("layers", "Matching Events", f.match_count) +
        "</div></div></div>" +
        '<div id="f-tabs" class="tabs" role="tablist">' +
        ["Timeline", "Risk", "Notes", "Raw"].map(function (t, i) {
          return '<button class="tab' + (i === 0 ? " active" : "") + '" data-tab="' + t.toLowerCase() + '">' + t + "</button>";
        }).join("") + "</div>" +
        '<div class="card" style="margin-top:14px"><div class="card-body" id="f-panel">' + QL.loading("Loading…") + "</div></div>";

      function switchTab(name) {
        $$("#f-tabs .tab").forEach(function (t) { t.classList.toggle("active", t.dataset.tab === name); });
        loadPanel(name);
      }
      $$("#f-tabs .tab").forEach(function (t) {
        t.addEventListener("click", function () { switchTab(t.dataset.tab); });
      });

      function loadPanel(name) {
        var panel = $("#f-panel");
        if (name === "timeline") {
          api("/findings/" + id + "/events").then(function (d) {
            panel.innerHTML = '<div class="small muted" style="margin-bottom:10px">' + (d.total || 0) +
              " events · window " + QL.fmtDateTime(d.window.start) + " → " + QL.fmtDateTime(d.window.end) + "</div>" +
              QL_.timelineHtml(d.events || []);
            QL_.bindTimeline(panel);
          }).catch(function (e) { panel.innerHTML = QL.emptyState({ icon: "warning", title: e.message }); });
        } else if (name === "risk") {
          api("/findings/" + id + "/risk").then(function (d) {
            var ents = d.entities || [];
            if (!ents.length) {
              panel.innerHTML = QL.emptyState({ icon: "gauge", title: "No entities", sub: "This finding has no user, host or IP to score." });
              return;
            }
            panel.innerHTML = ents.map(function (en) {
              var contribs = (en.contributions || []).slice(0, 12);
              return '<div style="margin-bottom:14px">' +
                '<div class="flex-between" style="margin-bottom:6px"><span class="flex">' + QL.icon(QL.entityIcon(en.type)) +
                ' <b class="mono small">' + QL.esc(en.value) + '</b> <span class="faint small">' + en.type + "</span></span>" +
                ' <span class="flex">' + QL.riskBar(en.risk_score, 110) + " " + QL.riskBadge(en.risk_score, false) + "</span></div>" +
                (contribs.length ? '<div class="small" style="display:flex;flex-direction:column;gap:4px">' + contribs.map(function (c) {
                  return '<div class="flex-between"><span class="muted">' + QL.esc(c.source_type) +
                    (c.description ? " · " + QL.esc(c.description) : "") + '</span><span class="mono" style="color:' + QL.riskColor(c.points) + '">+' + c.points + "</span></div>";
                }).join("") + "</div>" : "") + "</div>";
            }).join("");
          }).catch(function (e) { panel.innerHTML = QL.emptyState({ icon: "warning", title: e.message }); });
        } else if (name === "notes") {
          panel.innerHTML = '<div class="field" style="margin-bottom:12px"><label>Analyst note</label>' +
            '<textarea class="textarea" id="f-note-input" placeholder="Add an analyst note…"></textarea></div>' +
            '<div class="flex" style="justify-content:flex-end;margin-bottom:14px"><button class="btn btn-sm btn-primary" id="f-note-add">' + QL.icon("plus") + " Add Note</button></div>" +
            '<div id="f-notes">' + (f.notes && f.notes.length
              ? f.notes.map(function (n) { return QL_.noteItem(n.author, n.content, n.created_at); }).join("")
              : '<div class="empty"><p>No notes yet.</p></div>') + "</div>";
          $("#f-note-add").addEventListener("click", function () {
            var v = $("#f-note-input").value.trim();
            if (!v) return;
            api("/findings/" + id + "/notes", { method: "POST", body: { content: v } }).then(function () {
              QL.toast("Note added");
              api("/findings/" + id).then(function (nf) { f = nf; loadPanel("notes"); });
            }).catch(function (e) { QL.toast(e.message, "error"); });
          });
        } else {
          panel.innerHTML = '<pre class="mono" style="font-size:11.5px;background:var(--ql-bg-deep);border:1px solid var(--ql-border-soft);border-radius:8px;padding:14px;overflow:auto;max-height:420px">' +
            QL.esc(JSON.stringify({
              id: f.id, title: f.title, severity: f.severity, status: f.status, risk_score: f.risk_score,
              user: f.user, host: f.host, source_ip: f.source_ip, destination_ip: f.destination_ip,
              mitre: f.mitre_tactic ? [f.mitre_tactic, f.mitre_technique] : f.mitre_technique,
              tags: f.tags, event_ids: f.event_ids, first_seen: f.first_seen, last_seen: f.last_seen,
            }, null, 2)) + "</pre>";
        }
      }
      switchTab("timeline");

      $("#f-assign").addEventListener("click", function () {
        var close = QL.modal({
          title: "Assign finding",
          body: '<div class="field"><label for="fa-user">Analyst</label><input class="input" id="fa-user" placeholder="username" value="' + QL.esc(f.owner || "") + '"></div>',
          footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>Assign</button>',
        });
        close.el.addEventListener("click", function (e) {
          if (e.target.dataset.x) close();
          if (e.target.dataset.ok) {
            var v = $("#fa-user").value.trim();
            if (!v) return;
            api("/findings/" + id, { method: "PATCH", body: { owner: v } }).then(function (u) {
              close(); QL.toast("Assigned to " + v); f = u; QL_.route();
            }).catch(function (er) { QL.toast(er.message, "error"); });
          }
        });
      });

      $("#f-status").addEventListener("click", function () {
        QL_.statusModal(f.status, function (st) {
          api("/findings/" + id, { method: "PATCH", body: { status: st } }).then(function (u) {
            QL.toast("Status → " + st); f = u; QL_.route();
          }).catch(function (e) { QL.toast(e.message, "error"); });
        });
      });

      $("#f-investigate").addEventListener("click", function () {
        QL_.createInvestigationModal([f.id], true, f.title, f.severity);
      });
    }).catch(function (e) {
      page.innerHTML = QL.emptyState({ icon: "warning", title: "Finding not found", sub: e.message,
        action: '<a class="btn" href="#/queue">Back to queue</a>' });
    });
  };

  function mitreChip(tactic, technique) {
    if (!tactic && !technique) return "";
    return '<span class="badge" style="background:var(--ql-sev-info-bg);color:var(--ql-sev-info)">' +
      QL.icon("crosshair") + " " + QL.esc(tactic ? tactic + " · " : "") + QL.esc(technique || "") + "</span>";
  }

  /* ═══ Investigations list ══════════════════════════════════ */
  window.QLP.investigations = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Investigations", "Security stories under active work",
      '<button class="btn btn-primary" id="i-new">' + QL.icon("plus") + " Create Investigation</button>") +
      '<div class="card card-flush" id="i-table">' + QL.loading("Loading…") + "</div>";

    load();
    function load() {
      api("/investigations?limit=50").then(function (d) {
        var list = d.investigations || [];
        if (!list.length) {
          $("#i-table").innerHTML = QL.emptyState({
            dragon: true,
            title: "No investigations yet.",
            sub: "Your little dragon is waiting for something suspicious.",
            action: '<a class="btn" href="#/search">' + QL.icon("search") + " Explore Search</a>",
          });
          return;
        }
        $("#i-table").innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Severity</th><th>Title</th><th>Findings</th><th>Assignee</th><th>Status</th><th>Updated</th></tr></thead><tbody>" +
          list.map(function (iv) {
            return '<tr class="row-sev ' + QL.normSev(iv.severity) + '" data-i="' + iv.id + '">' +
              "<td>" + QL.sevBadge(iv.severity) + "</td>" +
              '<td class="cell-title">' + QL.esc(iv.title) +
              (iv.description ? '<div class="cell-muted" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + QL.esc(iv.description) + "</div>" : "") +
              "</td>" +
              '<td class="cell-mono">' + (iv.finding_ids || []).length + "</td>" +
              "<td>" + (iv.assignee
                ? '<span class="flex" style="gap:6px"><span class="avatar" style="width:22px;height:22px;font-size:10px">' + QL.esc(iv.assignee.slice(0, 2).toUpperCase()) + "</span>" + QL.esc(iv.assignee) + "</span>"
                : '<span class="faint">—</span>') + "</td>" +
              "<td>" + QL.statusBadge(iv.status) + "</td>" +
              '<td class="cell-muted nowrap">' + QL.fmtAgo(iv.updated_at) + "</td></tr>";
          }).join("") + "</tbody></table></div>";
        $$("#i-table tr[data-i]").forEach(function (tr) {
          tr.classList.add("clickable");
          tr.addEventListener("click", function () { location.hash = "#/investigation/" + tr.dataset.i; });
        });
      }).catch(function (e) {
        $("#i-table").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load", sub: e.message });
      });
    }

    $("#i-new").addEventListener("click", function () { QL_.createInvestigationModal([], false); });
  };

  /* ═══ Investigation detail ═════════════════════════════════ */
  window.QLP.investigation = function (id) {
    var page = $("#page");
    api("/investigations/" + encodeURIComponent(id)).then(function (iv) {
      page.innerHTML =
        '<div class="flex" style="margin-bottom:12px"><a class="btn btn-ghost btn-sm" href="#/investigations">' + QL.icon("arrow-left") + " All investigations</a></div>" +
        '<div class="page-header"><div style="min-width:0">' +
        '<div class="flex" style="gap:8px;flex-wrap:wrap;margin-bottom:8px">' + QL.sevBadge(iv.severity) +
        " " + QL.statusBadge(iv.status) +
        (iv.assignee ? '<span class="badge" style="background:var(--ql-surface-2);color:var(--ql-text-2)">' + QL.icon("user") + " " + QL.esc(iv.assignee) + "</span>" : "") +
        "</div>" +
        '<h1 style="font-size:24px">' + QL.esc(iv.title) + "</h1>" +
        (iv.description ? '<div class="page-sub" style="max-width:760px;margin-top:6px">' + QL.esc(iv.description) + "</div>" : "") +
        "</div><div class='page-actions'>" +
        '<button class="btn" id="i-assign">' + QL.icon("user") + " Assign</button>" +
        '<button class="btn" id="i-status">' + QL.icon("clock") + " Change Status</button>" +
        '<button class="btn" id="i-evidence">' + QL.icon("database") + " Add Evidence</button>" +
        '<button class="btn" id="i-finding">' + QL.icon("link") + " Link Finding</button>" +
        "</div></div>" +
        '<div class="card" style="margin-bottom:14px"><div class="card-body"><div class="kv-grid">' +
        QL.kv("layers", "Linked Findings", (iv.finding_ids || []).length) +
        QL.kv("database", "Evidence Events", (iv.event_ids || []).length) +
        QL.kv("entities", "Entities", (iv.entities || []).length) +
        QL.kv("terminal", "Saved Queries", (iv.queries || []).length) +
        QL.kv("crosshair", "Techniques", (iv.techniques || []).join(", "), true) +
        QL.kv("clock", "Created", QL.fmtDateTime(iv.created_at)) +
        "</div></div></div>" +
        '<div id="i-tabs" class="tabs" role="tablist">' +
        ["Timeline", "Findings", "Entities", "MITRE", "Notes", "Activity"].map(function (t, i) {
          return '<button class="tab' + (i === 0 ? " active" : "") + '" data-tab="' + t.toLowerCase() + '">' + t + "</button>";
        }).join("") + "</div>" +
        '<div class="card" style="margin-top:14px"><div class="card-body" id="i-panel">' + QL.loading("Loading…") + "</div></div>";

      var state = { events: null };

      function loadEvents() {
        if (state.events) return Promise.resolve(state.events);
        var ids = (iv.event_ids || []).slice(0, 60);
        if (!ids.length) return Promise.resolve(state.events = []);
        return Promise.all(ids.map(function (eid) {
          return api("/events/" + encodeURIComponent(eid)).catch(function () { return null; });
        })).then(function (evs) {
          state.events = evs.filter(Boolean).sort(function (a, b) {
            return new Date(a.timestamp) - new Date(b.timestamp);
          });
          return state.events;
        });
      }

      function switchTab(name) {
        $$("#i-tabs .tab").forEach(function (t) { t.classList.toggle("active", t.dataset.tab === name); });
        var panel = $("#i-panel");
        if (name === "timeline") {
          panel.innerHTML = QL.loading("Reconstructing the timeline…");
          loadEvents().then(function (evs) {
            var html = evs.length ? '<div class="small muted" style="margin-bottom:10px">' + evs.length + " evidence events</div>" + QL_.timelineHtml(evs) : "";
            var notes = (iv.notes || []).map(function (n) {
              return '<div class="tl-item"><span class="tl-marker note">' + QL.icon("note") + "</span>" +
                '<div class="tl-time">' + QL.fmtDateTime(n.created_at) + "</div>" +
                '<div class="tl-head"><span class="tl-title">Note</span></div>' +
                '<div class="tl-meta">' + QL.esc(n.author || "analyst") + "</div>" +
                '<div class="tl-detail" style="display:block">' + QL.esc(n.body) + "</div></div>";
            }).join("");
            panel.innerHTML = (html || notes) ||
              QL.emptyState({ icon: "activity", title: "Nothing here yet", sub: "Attach events as evidence to build the timeline." });
            QL_.bindTimeline(panel);
          }).catch(function (e) { panel.innerHTML = QL.emptyState({ icon: "warning", title: e.message }); });
        } else if (name === "findings") {
          api("/investigations/" + id + "/findings").then(function (d) {
            var list = d.findings || [];
            if (!list.length) {
              panel.innerHTML = QL.emptyState({ icon: "queue", title: "No linked findings", sub: "Link findings to connect the story." });
              return;
            }
            panel.innerHTML = '<div class="finding-cards">' + list.map(function (f) {
              return '<div class="finding-card" data-f="' + f.id + '">' +
                '<div class="fc-top">' + QL.sevBadge(f.severity) + " " + QL.riskBadge(f.risk_score, false) + "</div>" +
                '<div class="fc-title">' + QL.esc(f.title) + "</div>" +
                '<div class="kv-grid">' +
                QL.kv("user", "User", f.user) +
                QL.kv("host", "Host", f.host) +
                QL.kv("crosshair", "MITRE", f.mitre_technique, true) +
                QL.kv("clock", "First Seen", f.first_seen ? QL.fmtTime(f.first_seen) : "") +
                "</div>" +
                '<div class="fc-foot">' + QL.statusBadge(f.status) +
                '<span class="small flex" style="color:var(--ql-text-muted)">' + QL.icon("eye") + " Open</span></div></div>";
            }).join("") + "</div>";
            $$("#i-panel .finding-card").forEach(function (c) {
              c.addEventListener("click", function () { location.hash = "#/finding/" + c.dataset.f; });
            });
          }).catch(function (e) { panel.innerHTML = QL.emptyState({ icon: "warning", title: e.message }); });
        } else if (name === "entities") {
          var ents = iv.entities || [];
          if (!ents.length) {
            panel.innerHTML = QL.emptyState({ icon: "entities", title: "No entities tracked", sub: "Entities are extracted from linked findings and events." });
            return;
          }
          panel.innerHTML = QL.loading("Mapping relationships…");
          var center = ents[0];
          Promise.all(ents.slice(0, 4).map(function (en) {
            return api("/entities/" + encodeURIComponent(en.type) + "/" + encodeURIComponent(en.value)).catch(function () { return null; });
          })).then(function (details) {
            var neighbors = [];
            details.filter(Boolean).forEach(function (d) {
              (d.neighbors || []).forEach(function (nb) {
                if (neighbors.some(function (x) { return x.value === nb.value && x.type === nb.type; })) return;
                if (nb.value === center.value && nb.type === center.type) return;
                neighbors.push(nb);
              });
            });
            panel.innerHTML = QL_.entityGraphHtml(center, neighbors.slice(0, 8)) +
              '<div class="small muted" style="text-align:center;margin-top:6px">' +
              ents.length + " tracked entit" + (ents.length === 1 ? "y" : "ies") + " · " + neighbors.length + " observed relationship" + (neighbors.length === 1 ? "" : "s") + "</div>" +
              '<div class="entity-list" style="margin-top:14px;max-width:520px;margin-left:auto;margin-right:auto" id="i-entity-list">' +
              ents.map(function (en) {
                return QL_.entityRow(en.type, en.value, 0, null);
              }).join("") + "</div>";
            QL_.bindGraph(panel);
            /* enrich tracked rows with real risk where possible */
            Promise.all(ents.slice(0, 8).map(function (en, i) {
              var riskType = ["user", "host", "ip"].indexOf(en.type) > -1 ? en.type : null;
              if (!riskType) return Promise.resolve(null);
              return api("/risk/entities?type=" + riskType + "&limit=100").then(function (d) {
                var match = (d.entities || []).find(function (x) { return x.value === en.value; });
                return { i: i, r: match };
              }).catch(function () { return null; });
            })).then(function (risks) {
              risks.forEach(function (res) {
                if (res && res.r) {
                  var rows = $$("#i-entity-list .entity-row");
                  if (rows[res.i]) rows[res.i].outerHTML = QL_.entityRow(ents[res.i].type, ents[res.i].value, res.r.risk_score, res.r.findings);
                }
              });
              QL_.bindEntityRows($("#i-entity-list"));
            });
          });
        } else if (name === "mitre") {
          var techs = iv.techniques || [];
          panel.innerHTML = techs.length
            ? '<div class="mitre-list">' + techs.map(function (t) {
                return '<div class="mitre-row"><span class="mitre-code">' + QL.esc(t) + "</span>" +
                  '<div class="mitre-name">' + techniqueName(t) + '</div><span class="faint small">from finding links</span></div>';
              }).join("") + "</div>"
            : QL.emptyState({ icon: "crosshair", title: "No techniques tagged", sub: "Linked findings carry MITRE ATT&CK technique references." });
        } else if (name === "notes") {
          panel.innerHTML = '<div class="field" style="margin-bottom:14px"><label>Timeline note</label>' +
            '<textarea class="textarea" id="i-note-input" placeholder="Add to the investigation timeline…"></textarea></div>' +
            '<div class="flex" style="justify-content:flex-end;margin-bottom:14px"><button class="btn btn-sm btn-primary" id="i-note-add">' + QL.icon("plus") + " Add Note</button></div>" +
            "<div>" + (iv.notes && iv.notes.length
              ? iv.notes.map(function (n) { return QL_.noteItem(n.author, n.body, n.created_at); }).join("")
              : '<div class="empty"><p>No notes yet.</p></div>') + "</div>";
          $("#i-note-add").addEventListener("click", function () {
            var v = $("#i-note-input").value.trim();
            if (!v) return;
            api("/investigations/" + id + "/notes", { method: "POST", body: { body: v } }).then(function () {
              QL.toast("Note added to timeline");
              api("/investigations/" + id).then(function (u) { iv = u; switchTab("notes"); });
            }).catch(function (e) { QL.toast(e.message, "error"); });
          });
        } else {
          api("/response-actions/history?limit=30").then(function (hist) {
            var list = (hist || []).slice(0, 30);
            if (!list.length) {
              panel.innerHTML = QL.emptyState({ icon: "zap", title: "No response actions yet", sub: "Executed containment and triage actions appear here." });
              return;
            }
            panel.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr><th>Action</th><th>Target</th><th>Owner</th><th>Points</th><th>When</th></tr></thead><tbody>' +
              list.map(function (h) {
                return "<tr><td>" + QL.esc(h.action || h.name || "") + '</td><td class="cell-mono">' + QL.esc(h.target || "") +
                  "</td><td>" + QL.esc(h.owner || h.user || "—") + '</td><td class="cell-mono">' + (h.points != null ? h.points : "") +
                  '</td><td class="cell-muted">' + (h.created_at ? QL.fmtAgo(h.created_at) : "") + "</td></tr>";
              }).join("") + "</tbody></table></div>";
          }).catch(function (e) { panel.innerHTML = QL.emptyState({ icon: "warning", title: e.message }); });
        }
      }

      $$("#i-tabs .tab").forEach(function (t) {
        t.addEventListener("click", function () { switchTab(t.dataset.tab); });
      });
      switchTab("timeline");

      $("#i-assign").addEventListener("click", function () {
        var close = QL.modal({
          title: "Assign investigation",
          body: '<div class="field"><label for="ia-user">Analyst</label><input class="input" id="ia-user" value="' + QL.esc(iv.assignee || "") + '"></div>',
          footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>Assign</button>',
        });
        close.el.addEventListener("click", function (e) {
          if (e.target.dataset.x) close();
          if (e.target.dataset.ok) {
            var v = $("#ia-user").value.trim();
            if (!v) return;
            api("/investigations/" + id, { method: "PATCH", body: { assignee: v } }).then(function (u) {
              close(); QL.toast("Assigned to " + v); iv = u; QL_.route();
            }).catch(function (er) { QL.toast(er.message, "error"); });
          }
        });
      });

      $("#i-status").addEventListener("click", function () {
        QL_.statusModal(iv.status, function (st) {
          api("/investigations/" + id + "/status", { method: "POST", body: { status: st } }).then(function (u) {
            QL.toast("Status → " + st); iv = u; QL_.route();
          }).catch(function (e) { QL.toast(e.message, "error"); });
        });
      });

      $("#i-evidence").addEventListener("click", function () {
        var close = QL.modal({
          title: "Add evidence",
          body: '<div class="field"><label for="ev-spl">SPL query to attach</label>' +
            '<input class="input input-mono" id="ev-spl" placeholder="user=jsmith AND host=workstation-42" value="search"></div>' +
            '<div class="field"><label for="ev-limit">Events to attach</label>' +
            '<select class="select" id="ev-limit"><option>10</option><option selected>25</option><option>50</option></select></div>' +
            '<div class="field-hint">The first N matching events are attached as evidence.</div>',
          footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>' + QL.icon("play") + " Run &amp; Attach</button>",
        });
        close.el.addEventListener("click", function (e) {
          if (e.target.dataset.x) close();
          if (e.target.dataset.ok) {
            var q = $("#ev-spl").value.trim() || "search";
            var n = Number($("#ev-limit").value);
            api("/search", { method: "POST", body: { query: q, limit: n } }).then(function (d) {
              var rows = d.results || [];
              var ids = rows.map(function (r) { return r.id; }).filter(Boolean);
              if (!ids.length) { QL.toast("No events matched", "error"); return; }
              return api("/investigations/" + id + "/evidence", { method: "POST", body: { event_ids: ids } })
                .then(function (u) {
                  close();
                  QL.toast(ids.length + " events attached");
                  iv = u;
                  state.events = null;
                  QL_.route();
                });
            }).catch(function (er) { QL.toast(er.message, "error"); });
          }
        });
      });

      $("#i-finding").addEventListener("click", function () {
        var close = QL.modal({
          title: "Link finding",
          body: '<div class="field"><label for="if-id">Finding ID</label><input class="input input-mono" id="if-id" placeholder="uuid"></div>',
          footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>Link</button>',
        });
        close.el.addEventListener("click", function (e) {
          if (e.target.dataset.x) close();
          if (e.target.dataset.ok) {
            var v = $("#if-id").value.trim();
            if (!v) return;
            api("/investigations/" + id + "/findings", { method: "POST", body: { finding_ids: [v] } }).then(function (u) {
              close(); QL.toast("Finding linked"); iv = u; QL_.route();
            }).catch(function (er) { QL.toast(er.message, "error"); });
          }
        });
      });
    }).catch(function (e) {
      page.innerHTML = QL.emptyState({ icon: "warning", title: "Investigation not found", sub: e.message,
        action: '<a class="btn" href="#/investigations">Back</a>' });
    });
  };

  var _techniqueCache = null;
  function techniqueName(code) {
    if (!_techniqueCache) {
      api("/mitre/techniques").then(function (t) {
        _techniqueCache = {};
        (t || []).forEach(function (x) { if (x.id) _techniqueCache[x.id] = x.name; });
        $$(".mitre-name").forEach(function (el) {
          var row = el.closest(".mitre-row");
          var c = row && row.querySelector(".mitre-code");
          if (c && _techniqueCache[c.textContent]) el.textContent = _techniqueCache[c.textContent];
        });
      }).catch(function () {});
      return code;
    }
    return _techniqueCache[code] || code;
  }
})();
