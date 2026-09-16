/* ─────────────────────────────────────────────────────────────
   Quetzalog pages (SOC) — Scenarios, Attack Graph, Threat Models.
   Read-only views over the detection-engine scenario runs, the
   materialized attack graph and the multi-framework threat models.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";
  var QL_ = window.QL;
  var api = QL_.api;
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ═══ Scenario step / run badges ═══════════════════════════ */
  var STEP_COLORS = {
    observed: "var(--ql-success, #22c55e)",
    blocked: "var(--ql-text-muted, #9ca3af)",
    unknown: "var(--ql-warning, #f59e0b)",
    missing: "var(--ql-info, #38bdf8)",
    expected: "var(--ql-primary, #6366f1)",
  };

  function stepBadge(status) {
    var c = STEP_COLORS[status] || "var(--ql-text-muted)";
    return '<span class="badge badge-sev" style="border-color:' + c + '55;color:' + c + ';background:' + c + '14">' +
      '<span class="dot" style="background:' + c + '"></span>' + status + "</span>";
  }

  function runBadge(status) {
    var map = { active: "high", completed: "success", stale: "muted" };
    return '<span class="badge badge-sev ' + (map[status] || "muted") + '"><span class="dot"></span>' +
      QL_.esc(status || "unknown") + "</span>";
  }

  function scenarioName(def) {
    if (!def) return "scenario";
    if (typeof def === "object") return def.name || "scenario";
    try { return JSON.parse(def).name || "scenario"; } catch (e) { return "scenario"; }
  }

  /* ═══ Scenarios ════════════════════════════════════════════ */
  window.QLP.scenarios = function (id) {
    var page = $("#page");
    if (id) { renderRun(id); return; }
    renderList();

    function renderList() {
      page.innerHTML = QL_.pageHeader("Threat Scenarios", "Attack chains opened and advanced from mapped events — spec §6 of the detection engine",
        '<button class="btn" id="sc-refresh">' + QL.icon("refresh") + " Refresh</button>") +
        '<div class="card card-flush" id="sc-list">' + QL.loading("Checking the attack chains…") + "</div>";
      load();
      $("#sc-refresh").addEventListener("click", load);

      function load() {
        api("/scenarios").then(function (runs) {
          runs = runs || [];
          if (!runs.length) {
            $("#sc-list").innerHTML = QL.emptyState({
              icon: "timeline",
              title: "No scenario runs",
              sub: "Runs open automatically when a trigger technique is observed on a host (Scenarios must be enabled in config).",
            });
            return;
          }
          $("#sc-list").innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
            "<th>Scenario</th><th>Host</th><th>Status</th><th>Confidence</th><th>Risk</th><th>Opened</th><th>Closed</th></tr></thead><tbody>" +
            runs.map(function (r) {
              var host = (r.scope || "").replace(/^host:/, "");
              return '<tr data-id="' + r.id + '" class="clickable">' +
                '<td class="cell-title">' + QL.esc(scenarioName(r.definition)) + "</td>" +
                '<td class="cell-mono">' + QL.esc(host || "—") + "</td>" +
                "<td>" + runBadge(r.status) + "</td>" +
                '<td class="cell-muted">' + Math.round((r.confidence || 0) * 100) + "%</td>" +
                '<td class="cell-muted">' + Math.round(r.risk || 0) + "</td>" +
                '<td class="cell-muted nowrap">' + QL.fmtAgo(r.opened_at) + "</td>" +
                '<td class="cell-muted nowrap">' + (r.closed_at ? QL.fmtAgo(r.closed_at) : "—") + "</td>" +
                "</tr>";
            }).join("") + "</tbody></table></div>";
          $$("#sc-list tr[data-id]").forEach(function (tr) {
            tr.addEventListener("click", function () { location.hash = "#/scenarios/" + tr.dataset.id; });
          });
        }).catch(function (e) {
          $("#sc-list").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load scenarios", sub: e.message });
        });
      }
    }

    function renderRun(id) {
      api("/scenarios/" + encodeURIComponent(id)).then(function (d) {
        var run = d.run || {};
        var steps = d.steps || [];
        var wn = d.what_next || {};
        var host = (run.scope || "").replace(/^host:/, "");
        var observed = steps.filter(function (s) { return s.status === "observed"; }).length;

        page.innerHTML =
          '<div class="flex" style="margin-bottom:12px"><a class="btn btn-ghost btn-sm" href="#/scenarios">' +
          QL.icon("arrow-left") + " Back to scenarios</a></div>" +
          '<div class="page-header"><div style="min-width:0">' +
          "<h1>" + QL.esc(scenarioName(run.definition)) + "</h1>" +
          '<div class="page-sub">host <span class="mono">' + QL.esc(host || "—") + "</span> · " +
          observed + "/" + steps.length + " steps observed · risk " + Math.round(run.risk || 0) + " · confidence " +
          Math.round((run.confidence || 0) * 100) + "% · opened " + QL.fmtAgo(run.opened_at) + "</div></div>" +
          '<div class="page-actions">' + runBadge(run.status) +
          '<button class="btn" id="run-refresh">' + QL.icon("refresh") + " Refresh</button></div></div>" +

          '<div class="card" style="margin-bottom:14px"><div class="card-header"><div class="card-title">' +
          QL.icon("timeline") + " Attack chain</div></div><div class='card-body'>" +
          '<div class="scenario-steps">' +
          steps.map(function (s) {
            var ev = "";
            try { ev = (JSON.parse(s.evidence || "[]")).join(", "); } catch (e2) { ev = s.evidence || ""; }
            return '<div class="scenario-step" style="border-left-color:' + (STEP_COLORS[s.status] || "#888") + '">' +
              "<div class='flex-between' style='gap:8px'>" +
              '<div class="mono small" style="font-weight:700">' + QL.esc(s.technique || s.step_id) +
              (s.tactic ? ' <span class="faint">' + QL.esc(s.tactic) + "</span>" : "") + "</div>" +
              stepBadge(s.status) + "</div>" +
              (ev ? '<div class="small muted" style="margin-top:4px">' + QL.esc(ev) + "</div>" : "") +
              "</div>";
          }).join("") +
          "</div></div></div>" +

          '<div class="card"><div class="card-header"><div class="card-title">' +
          QL.icon("eye") + " What to expect next</div></div><div class='card-body'>" +
          (wn.expected && wn.expected.length
            ? '<div class="small" style="margin-bottom:8px"><b>Expected steps:</b> ' +
              wn.expected.map(function (s) { return '<span class="mono">' + QL.esc(s.technique || s.step_id) + "</span>"; }).join(", ") + "</div>"
            : '<div class="small muted" style="margin-bottom:8px">No expected steps remaining.</div>') +
          (wn.unknown && wn.unknown.length
            ? '<div class="small"><b>Cannot determine (telemetry gaps):</b><ul style="margin:6px 0 0 18px;padding:0">' +
              wn.unknown.map(function (s) { return "<li>" + QL.esc(s.technique || s.step_id) + "</li>"; }).join("") + "</ul></div>"
            : "") +
          "</div></div>";

        $("#run-refresh").addEventListener("click", function () { renderRun(id); });
      }).catch(function (e) {
        page.innerHTML = QL.emptyState({ icon: "warning", title: "Scenario run not found", sub: e.message,
          action: '<a class="btn" href="#/scenarios">Back to scenarios</a>' });
      });
    }
  };

  /* ═══ Attack Graph ═════════════════════════════════════════ */
  var AG = { states: ["observed", "inferred"], depth: 2 };

  window.QLP.attackgraph = function () {
    var page = $("#page");
    page.innerHTML =
      '<div class="page-header"><div><h1>Attack Graph</h1>' +
      '<div class="page-sub">Compromise state and materialized attack paths — observed, inferred and potential are never mixed</div></div>' +
      '<div class="page-actions">' +
      '<select class="select" id="ag-depth" aria-label="Depth" style="width:110px">' +
      [1, 2, 3, 4].map(function (d) { return '<option value="' + d + '"' + (d === AG.depth ? " selected" : "") + ">depth " + d + "</option>"; }).join("") +
      "</select>" +
      '<button class="btn btn-primary" id="ag-recompute">' + QL.icon("refresh") + " Recompute</button></div></div>" +

      '<div class="card" style="margin-bottom:14px"><div class="card-header"><div class="card-title">' +
      QL.icon("graph") + " Compromise state</div><span class='cell-muted small' id='ag-meta'></span></div>" +
      '<div class="card-body" id="ag-canvas">' + QL.loading("Evaluating compromise…") + "</div></div>" +

      '<div class="card"><div class="card-header"><div class="card-title">' +
      QL.icon("route") + " Attack paths</div></div><div class='card-body' id='ag-paths'>" +
      QL.loading("Loading paths…") + "</div></div>";

    loadGraph();
    loadPaths();

    $("#ag-depth").addEventListener("change", function () { AG.depth = Number(this.value); loadGraph(); });
    $("#ag-recompute").addEventListener("click", function () {
      QL.toast("Recompute requested (rate-limited to 60s)");
      loadGraph();
      loadPaths();
    });

    function loadGraph() {
      var q = "?depth=" + AG.depth + "&states=" + AG.states.join(",");
      api("/attack-graph" + q).then(function (sn) {
        var nodes = sn.nodes || [];
        var edges = sn.edges || [];
        var meta = $("#ag-meta");
        if (meta) meta.textContent = "generated " + QL.fmtDateTime(sn.generated_at) +
          (sn.truncated ? " · truncated" : "") + " · " + nodes.length + " nodes / " + edges.length + " edges";

        var comp = nodes.filter(function (n) { return /compromised/.test(n.compromise || ""); });
        var risk = nodes.filter(function (n) { return n.compromise === "at_risk_potential"; });

        var summary =
          '<div class="kv-grid" style="margin-bottom:10px">' +
          QL.kv("shieldAlert", "Compromised", comp.length, true) +
          QL.kv("target", "At risk", risk.length, true) +
          QL.kv("graph", "Nodes", nodes.length, true) +
          QL.kv("route", "Edges", edges.length, true) +
          "</div>";

        var canvas = $("#ag-canvas");
        if (!nodes.length) {
          canvas.innerHTML = summary + QL.emptyState({ icon: "graph", title: "No graph data",
            sub: "Relationships with evidence (login, exec, connect, …) build the graph. Ingest activity to populate it." });
          return;
        }
        canvas.innerHTML = summary + graphSvg(nodes, edges, comp, risk) +
          '<div class="small muted" style="margin-top:8px">Compromised: red · At risk: amber · boundary crossing: dashed · click a node for what-next</div>';

        var panel = $("#ag-whatnext");
        $$("#ag-canvas .ag-node").forEach(function (g) {
          g.addEventListener("click", function () {
            var t = g.dataset.t, v = g.dataset.v;
            whatNext(t, v, panel || canvas);
          });
        });
      }).catch(function (e) {
        var canvas = $("#ag-canvas");
        if (canvas) canvas.innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load attack graph", sub: e.message });
      });
    }

    // Bounded radial layout: compromised nodes innermost, at-risk next, the
    // rest outside. Deterministic ordering keeps re-renders stable.
    function graphSvg(nodes, edges, comp, risk) {
      var shown = nodes.slice(0, 60);
      var byId = {};
      shown.forEach(function (n) { byId[n.node] = n; });
      var W = 900, H = 460, cx = W / 2, cy = H / 2;

      var rings = [comp, risk, shown.filter(function (n) {
        return n.compromise !== "at_risk_potential" && !/compromised/.test(n.compromise || "");
      })];
      var radii = [0, 100, 190];
      var pos = {};
      rings.forEach(function (ring, ri) {
        ring.forEach(function (n, i) {
          if (ri === 0 && ring.length === 1) { pos[n.node] = { x: cx, y: cy }; return; }
          var ang = (i / Math.max(1, ring.length)) * Math.PI * 2 - Math.PI / 2 + ri * 0.4;
          pos[n.node] = { x: cx + radii[ri] * Math.cos(ang), y: cy + radii[ri] * Math.sin(ang) };
        });
      });

      var lines = edges.filter(function (e) { return byId[e.from] && byId[e.to]; }).slice(0, 200).map(function (e) {
        var a = pos[e.from], b = pos[e.to];
        var dash = e.crosses_boundary ? ' stroke-dasharray="5 4"' : "";
        var color = e.state === "inferred" ? "var(--ql-warning)" : "var(--ql-border)";
        return '<line x1="' + a.x + '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y +
          '" stroke="' + color + '" stroke-width="1.4"' + dash + "/>";
      }).join("");

      var blocks = shown.map(function (n) {
        var p = pos[n.node];
        var color = /compromised/.test(n.compromise || "") ? "var(--ql-danger, #ef4444)"
          : n.compromise === "at_risk_potential" ? "var(--ql-warning)" : "var(--ql-border)";
        var label = n.value.length > 20 ? n.value.slice(0, 19) + "…" : n.value;
        return '<g class="ag-node" data-t="' + QL.esc(n.type) + '" data-v="' + QL.esc(n.value) + '" style="cursor:pointer">' +
          '<circle cx="' + p.x + '" cy="' + p.y + '" r="26" fill="var(--ql-surface)" stroke="' + color + '" stroke-width="2"/>' +
          '<text class="ag-label" x="' + p.x + '" y="' + (p.y - 2) + '" text-anchor="middle">' + QL.esc(label) + "</text>" +
          '<text class="ag-sub" x="' + p.x + '" y="' + (p.y + 13) + '" text-anchor="middle">' +
          QL.esc(n.criticality || n.type) + "</text></g>";
      }).join("");

      return '<div class="ag-wrap"><svg viewBox="0 0 ' + W + " " + H + '" width="' + W + '" height="' + H + '">' +
        lines + blocks + "</svg></div>";
    }

    function whatNext(t, v, root) {
      var el = document.createElement("div");
      el.className = "card";
      el.id = "ag-whatnext";
      el.style.cssText = "margin-top:12px";
      el.innerHTML = '<div class="card-header"><div class="card-title">' + QL.icon("eye") +
        " What next · <span class='mono'>" + QL.esc(t + ":" + v) + "</span></div></div>" +
        '<div class="card-body">' + QL.loading("…") + "</div>";
      root.appendChild(el);
      el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      api("/attack-graph/nodes/" + encodeURIComponent(t) + "/" + encodeURIComponent(v) + "/what-next")
        .then(function (d) {
          var techs = (d.expected_techniques || []).join(", ");
          el.innerHTML = '<div class="card-header"><div class="card-title">' + QL.icon("eye") +
            " What next · <span class='mono'>" + QL.esc(t + ":" + v) + "</span></div></div>" +
            '<div class="card-body">' +
            '<div class="small" style="margin-bottom:8px"><b>Expected techniques:</b> ' +
            (techs ? '<span class="mono">' + QL.esc(techs) + "</span>" : "none") + "</div>" +
            '<div class="small"><b>Potential next hops:</b> ' +
            (d.potential_edges && d.potential_edges.length
              ? d.potential_edges.slice(0, 8).map(function (e) {
                  return '<span class="badge badge-sev muted"><span class="dot"></span>' +
                    QL.esc(e.relation) + " → " + QL.esc(e.to) + "</span>";
                }).join(" ")
              : "none observed") + "</div></div>";
        }).catch(function (e2) {
          el.remove();
          QL.toast(e2.message, "error");
        });
    }

    function loadPaths() {
      api("/attack-graph/paths").then(function (d) {
        var paths = (d && d.paths) || d || [];
        paths = paths || [];
        var el = $("#ag-paths");
        if (!el) return;
        if (!paths.length) {
          el.innerHTML = QL.emptyState({ icon: "route", title: "No materialized attack paths",
            sub: "Paths materialize when compromise evidence crosses a trust boundary. They recompute hourly." });
          return;
        }
        el.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Status</th><th>From</th><th>To</th><th>Risk</th><th>Description</th><th>Created</th></tr></thead><tbody>" +
          paths.map(function (p) {
            var statusMap = { observed: "success", inferred: "high", potential: "muted" };
            return '<tr data-path="' + p.id + '" class="clickable">' +
              '<td><span class="badge badge-sev ' + (statusMap[p.status] || "muted") + '"><span class="dot"></span>' + p.status + "</span></td>" +
              '<td class="cell-mono">' + QL.esc(p.source_node) + "</td>" +
              '<td class="cell-mono">' + QL.esc(p.target_node) + "</td>" +
              '<td class="cell-muted">' + Math.round(p.risk || 0) + "</td>" +
              '<td class="cell-muted">' + QL.esc(p.description || "") + "</td>" +
              '<td class="cell-muted nowrap">' + (p.created_at ? QL.fmtAgo(p.created_at) : "—") + "</td>" +
              "</tr>";
          }).join("") + "</tbody></table></div>";
        $$("#ag-paths tr[data-path]").forEach(function (tr) {
          tr.addEventListener("click", function () { pathDetail(tr.dataset.path, el); });
        });
      }).catch(function (e) {
        var el = $("#ag-paths");
        if (el) el.innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load paths", sub: e.message });
      });
    }

    function pathDetail(id, root) {
      api("/attack-graph/paths/" + encodeURIComponent(id)).then(function (p) {
        var steps = p.steps || [];
        var box = document.createElement("div");
        box.className = "card";
        box.style.cssText = "margin-top:12px";
        box.innerHTML = '<div class="card-header"><div class="card-title">' + QL.icon("route") +
          " Path · <span class='mono'>" + QL.esc(p.source_node) + " → " + QL.esc(p.target_node) + "</span> " +
          '<span class="badge badge-sev muted"><span class="dot"></span>' + QL.esc(p.status) + "</span></div></div>" +
          '<div class="card-body">' +
          (steps.length
            ? '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
              "<th>#</th><th>Edge</th><th>State</th><th>Technique</th><th>Evidence</th></tr></thead><tbody>" +
              steps.map(function (s) {
                return "<tr>" +
                  '<td class="cell-muted">' + s.pos + "</td>" +
                  '<td class="cell-mono">' + QL.esc(s.from_node) + " → " + QL.esc(s.to_node) +
                  (s.edge_relation ? ' <span class="faint">' + QL.esc(s.edge_relation) + "</span>" : "") + "</td>" +
                  '<td><span class="badge badge-sev muted"><span class="dot"></span>' + QL.esc(s.edge_state) + "</span></td>" +
                  '<td class="cell-mono small">' + QL.esc(s.technique || "—") + "</td>" +
                  '<td class="cell-mono small" title="' + QL.esc(s.evidence || "") + '">' +
                  QL.esc(s.evidence ? s.evidence.slice(0, 120) : "—") + "</td>" +
                  "</tr>";
              }).join("") + "</tbody></table></div>"
            : '<div class="small muted">No per-step evidence recorded.</div>') +
          "</div>";
        root.appendChild(box);
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }).catch(function (e) { QL.toast(e.message, "error"); });
    }
  };

  /* ═══ Telemetry Coverage ═══════════════════════════════════ */
  window.QLP.coverage = function (assetId) {
    var page = $("#page");
    page.innerHTML =
      '<div class="page-header"><div><h1>Telemetry Coverage</h1>' +
      '<div class="page-sub">What is actually observed per asset — “no evidence” is not the same as “no activity”; gaps are highlighted, stale feeds marked</div></div></div>' +
      '<div class="card card-flush" id="cov-list">' + QL.loading("Computing coverage…") + "</div>";

    if (assetId) { loadDetail(assetId); return; }
    loadList();

    function loadList() {
      api("/coverage/summary").then(function (d) {
        var assets = (d && d.assets) || [];
        if (!assets.length) {
          $("#cov-list").innerHTML = QL.emptyState({
            icon: "eye",
            title: "No assets yet",
            sub: "Coverage is computed for registered assets (Assets are created via the API/UI). Add assets to see their telemetry matrix.",
          });
          return;
        }
        $("#cov-list").innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Asset</th><th>Type</th><th>Coverage</th><th>Available</th><th class='gap-col'>Missing (gaps)</th><th>Stale</th></tr></thead><tbody>" +
          assets.map(function (a) {
            var chips = function (list, cls, empty) {
              if (!list || !list.length) return '<span class="faint">' + (empty || "—") + "</span>";
              return list.map(function (s) {
                return '<span class="badge ' + cls + '"><span class="dot"></span>' + QL.esc(s) + "</span>";
              }).join(" ");
            };
            return '<tr class="clickable" data-asset="' + a.asset_id + '">' +
              '<td class="cell-title">' + QL.esc(a.asset_name) + "</td>" +
              '<td class="cell-muted">' + QL.esc(a.entity_type) + "</td>" +
              '<td>' + QL.riskBar(a.coverage_pct, 90) + ' <span class="mono small">' + Math.round(a.coverage_pct || 0) + "%</span></td>" +
              '<td><div class="ev-chips">' + chips(a.available, "cov-ok", "none") + "</div></td>" +
              '<td><div class="ev-chips">' + chips(a.missing, "cov-missing") + "</div></td>" +
              '<td><div class="ev-chips">' + chips(a.stale, "cov-stale") + "</div></td>" +
              "</tr>";
          }).join("") + "</tbody></table></div>";
        $$("#cov-list tr[data-asset]").forEach(function (tr) {
          tr.addEventListener("click", function () { location.hash = "#/coverage/" + tr.dataset.asset; });
        });
      }).catch(function (e) {
        $("#cov-list").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load coverage", sub: e.message });
      });
    }

    function loadDetail(assetId) {
      api("/coverage/assets/" + encodeURIComponent(assetId)).then(function (d) {
        var cov = d.coverage || {};
        var rows = d.rows || [];
        var staleSet = {};
        (cov.stale || []).forEach(function (s) { staleSet[s] = true; });
        var chips = function (list, cls) {
          if (!list || !list.length) return "";
          return list.map(function (s) {
            return '<span class="badge ' + cls + '"><span class="dot"></span>' + QL.esc(s) + "</span>";
          }).join(" ");
        };
        page.innerHTML =
          '<div class="flex" style="margin-bottom:12px"><a class="btn btn-ghost btn-sm" href="#/coverage">' +
          QL.icon("arrow-left") + " All assets</a></div>" +
          '<div class="page-header"><div style="min-width:0">' +
          "<h1>" + QL.esc(cov.asset_name || "Asset") + "</h1>" +
          '<div class="page-sub">' + QL.esc(cov.entity_type || "") +
          (cov.os ? " · " + QL.esc(cov.os) : "") + " · computed " + QL.fmtDateTime(cov.computed_at) + "</div></div>" +
          '<div class="page-actions"><span style="display:inline-flex;align-items:center;gap:8px">' +
          QL.riskBar(cov.coverage_pct, 120) + ' <span class="mono">' + Math.round(cov.coverage_pct || 0) + "%</span></span></div></div>" +
          '<div class="card" style="margin-bottom:14px"><div class="card-body"><div class="kv-grid">' +
          QL.kv("check", "Available", chips(cov.available, "cov-ok") || "—") +
          QL.kv("warning", "Missing", chips(cov.missing, "cov-missing") || "—") +
          QL.kv("clock", "Stale", chips(cov.stale, "cov-stale") || "—") +
          (cov.unexpected && cov.unexpected.length ? QL.kv("help", "Unexpected", chips(cov.unexpected, "cov-ok")) : "") +
          "</div></div></div>" +
          '<div class="card"><div class="card-header"><div class="card-title">' +
          QL.icon("layers") + " Source matrix</div></div><div class='card-body'>" +
          (rows.length
            ? '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
              "<th>Source class</th><th>Status</th><th>Expected</th><th>Collector</th><th>Last event</th><th>30d volume</th></tr></thead><tbody>" +
              rows.map(function (r) {
                var st = r.available
                  ? '<span class="badge cov-ok"><span class="dot"></span>available</span>'
                  : (staleSet[r.source_class]
                    ? '<span class="badge cov-stale"><span class="dot"></span>stale</span>'
                    : '<span class="badge cov-missing"><span class="dot"></span>missing</span>');
                return "<tr>" +
                  '<td class="cell-title">' + QL.esc(r.source_class) + "</td>" +
                  "<td>" + st + "</td>" +
                  '<td class="cell-muted">' + (r.expected ? "yes" : "no") + "</td>" +
                  '<td class="cell-mono small">' + QL.esc(r.collector || "—") + "</td>" +
                  '<td class="cell-muted nowrap">' + (r.last_event ? QL.fmtAgo(r.last_event) : "—") + "</td>" +
                  '<td class="cell-mono">' + (r.event_count_30d || 0) + "</td>" +
                  "</tr>";
              }).join("") + "</tbody></table></div>"
            : '<div class="small muted">No source classes declared for this asset.</div>') +
          "</div></div>";
      }).catch(function (e) {
        page.innerHTML = QL.emptyState({ icon: "warning", title: "Coverage not available", sub: e.message,
          action: '<a class="btn" href="#/coverage">All assets</a>' });
      });
    }
  };

  /* ═══ Threat Models ════════════════════════════════════════ */
  window.QLP.threatmodels = function () {
    var page = $("#page");
    page.innerHTML =
      '<div class="page-header"><div><h1>Threat Models</h1>' +
      '<div class="page-sub">STRIDE × kill-chain × ATT&CK × D3FEND, derived from live telemetry — labels stay honest (observed / inferred / assumed)</div></div>' +
      '<div class="page-actions"><button class="btn btn-primary" id="tm-new">' + QL.icon("plus") + " New model</button></div></div>" +
      '<div class="card card-flush" id="tm-list">' + QL.loading("Loading models…") + "</div>";
    load();
    $("#tm-new").addEventListener("click", newModel);

    function load() {
      api("/threat-models").then(function (models) {
        models = models || [];
        if (!models.length) {
          $("#tm-list").innerHTML = QL.emptyState({
            icon: "target",
            title: "No threat models",
            sub: "Create one, then refresh it to derive nodes, edges and threats from the current telemetry.",
            action: '<button class="btn" id="tm-new-2">' + QL.icon("plus") + " New model</button>",
          });
          var b = $("#tm-new-2");
          if (b) b.addEventListener("click", newModel);
          return;
        }
        $("#tm-list").innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Model</th><th>Source</th><th>Version</th><th>Status</th><th>Updated</th></tr></thead><tbody>" +
          models.map(function (m) {
            return '<tr data-id="' + m.id + '" class="clickable">' +
              '<td class="cell-title">' + QL.esc(m.name) +
              (m.scope ? ' <span class="faint small">' + QL.esc(m.scope) + "</span>" : "") + "</td>" +
              '<td class="cell-muted">' + QL.esc(m.source || "analyst") + "</td>" +
              '<td class="cell-muted">v' + (m.version || 1) + "</td>" +
              '<td class="cell-muted">' + QL.esc(m.status || "") + "</td>" +
              '<td class="cell-muted nowrap">' + (m.updated_at ? QL.fmtAgo(m.updated_at) : "—") + "</td>" +
              "</tr>";
          }).join("") + "</tbody></table></div>";
        $$("#tm-list tr[data-id]").forEach(function (tr) {
          tr.addEventListener("click", function () { location.hash = "#/threatmodel/" + tr.dataset.id; });
        });
      }).catch(function (e) {
        $("#tm-list").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load threat models", sub: e.message });
      });
    }

    function newModel() {
      var close = QL.modal({
        title: "New threat model",
        body:
          '<div class="field"><label for="tm-name">Name</label><input class="input" id="tm-name" placeholder="e.g. Corporate estate"></div>' +
          '<div class="field"><label for="tm-source">Source</label><select class="select" id="tm-source">' +
          '<option value="telemetry">telemetry — derived from live data</option>' +
          '<option value="analyst">analyst — manual</option>' +
          '<option value="hybrid">hybrid — derived + manually adjusted</option></select></div>' +
          '<div class="field"><label for="tm-scope">Scope (optional)</label><input class="input" id="tm-scope" placeholder="e.g. dmz, finance-vpc"></div>',
        footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>Create</button>',
      });
      close.el.addEventListener("click", function (e) {
        if (e.target.dataset.x) close();
        if (e.target.dataset.ok) {
          var name = $("#tm-name").value.trim();
          if (!name) { QL.toast("Name is required", "error"); return; }
          api("/threat-models", { method: "POST", body: {
            name: name, source: $("#tm-source").value, scope: $("#tm-scope").value.trim(),
          } }).then(function (m) {
            close();
            location.hash = "#/threatmodel/" + m.id;
          }).catch(function (er) { QL.toast(er.message, "error"); });
        }
      });
    }
  };

  window.QLP.threatmodel = function (id) {
    var page = $("#page");
    api("/threat-models/" + encodeURIComponent(id)).then(function (d) {
      var m = d.model || {};
      var nodes = d.nodes || [];
      var edges = d.edges || [];
      var threats = d.threats || [];
      var snaps = d.snapshots || [];

      var kindCounts = {};
      nodes.forEach(function (n) { kindCounts[n.kind] = (kindCounts[n.kind] || 0) + 1; });

      page.innerHTML =
        '<div class="flex" style="margin-bottom:12px"><a class="btn btn-ghost btn-sm" href="#/threatmodels">' +
        QL.icon("arrow-left") + " Back to threat models</a></div>" +
        '<div class="page-header"><div style="min-width:0"><h1>' + QL.esc(m.name) + "</h1>" +
        '<div class="page-sub">' + QL.esc(m.source || "analyst") + (m.scope ? " · " + QL.esc(m.scope) : "") +
        " · v" + (m.version || 1) + " · " + nodes.length + " nodes / " + edges.length + " edges / " + threats.length + " threats</div></div>" +
        '<div class="page-actions">' +
        (m.source !== "analyst"
          ? '<button class="btn" id="tm-refresh">' + QL.icon("refresh") + " Refresh from telemetry</button>"
          : '<span class="small muted">analyst model — edit manually</span>') +
        '<button class="btn btn-sm" id="tm-delete" style="color:var(--ql-danger,#ef4444)">' + QL.icon("trash") + " Delete</button>" +
        "</div></div>" +

        '<div class="card" style="margin-bottom:14px"><div class="card-header"><div class="card-title">' +
        QL.icon("shieldAlert") + " Threats</div></div><div class='card-body'>" +
        (threats.length ? '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
        "<th>Threat</th><th>Framework</th><th>Likelihood</th><th>Impact</th><th>Label</th><th>Techniques</th></tr></thead><tbody>" +
        threats.map(function (th) {
          return "<tr>" +
            '<td class="cell-title">' + QL.esc(th.description || th.threat_id) + "</td>" +
            '<td class="cell-muted">' + QL.esc(th.stride || th.kill_chain_phase || "—") + "</td>" +
            '<td class="cell-muted">' + QL.esc(th.likelihood || "—") + "</td>" +
            '<td>' + (th.impact ? QL.sevBadge(th.impact) : "—") + "</td>" +
            '<td><span class="badge badge-sev muted"><span class="dot"></span>' + QL.esc(th.label_state || "assumed") + "</span></td>" +
            '<td class="cell-mono small">' + QL.esc((th.techniques || []).join(", ")) + "</td>" +
            "</tr>";
        }).join("") + "</tbody></table></div>"
        : QL.emptyState({ icon: "shieldAlert", title: "No threats yet", sub: "Refresh the model to derive threats from the telemetry." })) +
        "</div></div>" +

        '<div class="grid" style="grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">' +
        '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("entities") + " Nodes</div></div>" +
        '<div class="card-body small">' +
        Object.keys(kindCounts).sort().map(function (k) {
          return '<div class="flex-between" style="padding:3px 0"><span>' + QL.esc(k) + '</span><span class="mono">' + kindCounts[k] + "</span></div>";
        }).join("") +
        "</div></div>" +
        '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("route") + " Edges (relationship)</div></div>" +
        '<div class="card-body small" style="max-height:260px;overflow:auto">' +
        (edges.length ? edges.slice(0, 40).map(function (e) {
          return '<div class="mono small" style="padding:3px 0">' + QL.esc(e.from_node || e.from) +
            ' <span class="faint">—' + QL.esc(e.relation || "") + "→</span> " + QL.esc(e.to_node || e.to) +
            ' <span class="badge badge-sev muted" style="margin-left:6px">' + QL.esc(e.label_state || e.state || "observed") + "</span></div>";
        }).join("") : "No edges yet.") +
        "</div></div></div>" +

        (snaps.length
          ? '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("clock") +
            " Drift history (model snapshots)</div></div><div class='card-body'>" +
            '<div class="table-wrap"><table class="ql-table"><thead><tr><th>Version</th><th>Triggered by</th><th>Changes</th></tr></thead><tbody>' +
            snaps.map(function (s) {
              var ch = {};
              if (s.changes) { try { ch = JSON.parse(s.changes); } catch (e) { ch = {}; } }
              var bits = [];
              if (ch.added_threats && ch.added_threats.length) bits.push("+ " + ch.added_threats.length + " threats");
              if (ch.removed_threats && ch.removed_threats.length) bits.push("− " + ch.removed_threats.length + " threats");
              if (ch.added_nodes && ch.added_nodes.length) bits.push("+ " + ch.added_nodes.length + " nodes");
              if (ch.removed_nodes && ch.removed_nodes.length) bits.push("− " + ch.removed_nodes.length + " nodes");
              if (ch.new_risks && ch.new_risks.length) bits.push('<span style="color:var(--ql-warning)">new risks: ' + ch.new_risks.length + "</span>");
              return "<tr><td class='cell-muted'>v" + s.version + "</td><td class='cell-muted'>" +
                QL.esc(s.triggered_by || "—") + "</td><td class='cell-muted small'>" +
                (bits.length ? bits.join(" · ") : "no changes") + "</td></tr>";
            }).join("") + "</tbody></table></div></div></div>"
          : "");

      var rf = $("#tm-refresh");
      if (rf) rf.addEventListener("click", function () {
        rf.disabled = true;
        api("/threat-models/" + id + "/refresh", { method: "POST", body: { triggered_by: "ui" } })
          .then(function (snap) {
            QL.toast("Model refreshed to v" + snap.version);
            window.QLP.threatmodel(id);
          }).catch(function (e) { QL.toast(e.message, "error"); rf.disabled = false; });
      });
      var dl = $("#tm-delete");
      if (dl) dl.addEventListener("click", function () {
        QL.confirmDialog("Delete this threat model?", "Nodes, edges, threats and drift history will be removed.", {
          danger: true, okLabel: "Delete",
          onOk: function () {
            api("/threat-models/" + id, { method: "DELETE" }).then(function () {
              QL.toast("Threat model deleted");
              location.hash = "#/threatmodels";
            }).catch(function (e) { QL.toast(e.message, "error"); });
          },
        });
      });
    }).catch(function (e) {
      page.innerHTML = QL.emptyState({ icon: "warning", title: "Threat model not found", sub: e.message,
        action: '<a class="btn" href="#/threatmodels">Back to threat models</a>' });
    });
  };
})();
