/* ─────────────────────────────────────────────────────────────
   Quetzalog pages (extra) — Search, SPL Builder, Detections,
   Risk, Entities, Threat Intel, Settings, 404.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";
  var QL_ = window.QL;
  var api = QL_.api;
  var S = QL_.state;
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  // Go duration strings ("2h5m3.412s", "900ms") -> "2h 5m 3s" / "900ms"
  function fmtUptime(d) {
    if (!d) return "";
    var s = String(d), total = 0, m;
    while ((m = s.match(/^(\d+(?:\.\d+)?)(h|ms|m|s)\/?/))) {
      total += parseFloat(m[1]) * ({ h: 3600, m: 60, s: 1, ms: 0.001 }[m[2]]);
      s = s.slice(m[0].length);
    }
    if (total < 1) return s || d;
    var h = Math.floor(total / 3600), mi = Math.floor((total % 3600) / 60), se = Math.round(total % 60);
    if (se === 60) { se = 0; mi++; }
    if (mi === 60) { mi = 0; h++; }
    var out = "";
    if (h) out += h + "h ";
    if (h || mi) out += mi + "m ";
    out += se + "s";
    return out;
  }

  function resultTable(cols, rows, maxRow) {
    var showCols = cols.length > 10
      ? ["timestamp", "severity", "host", "user", "source", "message"].filter(function (c) { return cols.indexOf(c) > -1; })
      : cols;
    if (!showCols.length) showCols = cols.slice(0, 8);
    return '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
      showCols.map(function (c) { return "<th>" + QL.esc(c) + "</th>"; }).join("") +
      "</tr></thead><tbody>" +
      rows.slice(0, maxRow || 250).map(function (row) {
        return "<tr>" + showCols.map(function (c) {
          var v = row[c];
          if (c === "timestamp") return '<td class="cell-mono nowrap">' + QL.fmtDateTime(v) + "</td>";
          if (c === "severity") return "<td>" + QL.sevBadge(v) + "</td>";
          if (v && typeof v === "object") v = JSON.stringify(v);
          var s = v == null ? "" : String(v);
          if (s.length > 160) s = s.slice(0, 157) + "…";
          return '<td class="' + (c === "message" ? "" : "cell-mono") + '" title="' + QL.esc(s) + '">' + QL.esc(s) + "</td>";
        }).join("") + "</tr>";
      }).join("") + "</tbody></table></div>";
  }

  /* ═══ Search ═══════════════════════════════════════════════ */
  window.QLP.search = function () {
    var page = $("#page");
    var q = S.searchPreset || "";
    S.searchPreset = "";

    page.innerHTML = QL_.pageHeader("Search", "Query security events with SPL",
      '<a class="btn" href="#/builder">' + QL.icon("blocks") + " SPL Builder</a>") +
      '<div class="card" style="margin-bottom:14px"><div class="card-body" style="padding:12px">' +
      '<div class="search-box" style="margin-bottom:10px"><span class="ic-lead">' + QL.icon("terminal") + "</span>" +
      '<input class="input input-mono" id="s-input" placeholder="index=auth user=jsmith | stats count by host" value="' + QL.esc(q) + '" style="padding-right:12px"></div>' +
      '<div class="filter-bar">' +
      QL_.sel("s-time", "Time", [["", "All time"], ["1h", "Last hour"], ["6h", "Last 6 hours"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"]], "") +
      QL_.sel("s-limit", "Limit", [["25", "25 results"], ["50", "50 results"], ["100", "100 results"], ["250", "250 results"]], "50") +
      '<button class="btn btn-primary" id="s-run">' + QL.icon("search") + " Search</button>" +
      "</div></div></div>" +
      '<div class="card card-flush"><div class="card-header"><span class="card-title" id="s-title">Results</span>' +
      '<span class="small faint" id="s-meta"></span></div>' +
      '<div class="card-body" id="s-results" style="padding:0">' +
      QL.emptyState({ icon: "search", title: "Run a query", sub: "Try a sample below, or press Enter in the input.",
        action: '<button class="btn btn-sm" id="s-sample">' + QL.icon("play") + " Sample query</button>" }) +
      "</div></div>";

    var sample = "index=auth OR user=* | stats count by user, host | sort count desc | head 20";
    var sampleBtn = $("#s-sample");
    if (sampleBtn) sampleBtn.addEventListener("click", function () {
      $("#s-input").value = sample;
      run();
    });
    $("#s-run").addEventListener("click", run);
    $("#s-input").addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });

    function run() {
      var query = $("#s-input").value.trim();
      if (!query) return;
      var el = $("#s-results");
      el.innerHTML = QL.loading("Searching…");
      var body = { query: query, limit: Number($("#s-limit").value) || 50 };
      var tr = $("#s-time").value;
      if (tr) { body.earliest = "-" + tr; body.latest = "now"; }
      api("/search", { method: "POST", body: body }).then(function (d) {
        var cols = d.columns || [];
        var rows = d.results || [];
        var total = d.total != null ? d.total : rows.length;
        $("#s-title").textContent = "Results · " + cols.length + " fields";
        $("#s-meta").textContent = total + " events" + (d.execution_ms != null ? " · " + Math.round(d.execution_ms) + " ms" : "");
        if (!rows.length) {
          el.innerHTML = QL.emptyState({ icon: "search", title: "No results", sub: "Try broadening the query or the time range." });
          return;
        }
        el.innerHTML = resultTable(cols, rows, 250);
      }).catch(function (e) {
        el.innerHTML = QL.emptyState({ icon: "warning", title: "Query failed", sub: e.message });
      });
    }

    if (q) run();
  };

  /* ═══ SPL Builder ══════════════════════════════════════════ */
  var B = {
    fields: [],
    time: { earliest: "24h", latest: "now" },
    stats: { on: false, fn: "count", field: "", alias: "", by: "" },
    sort: { on: false, field: "", desc: true },
    head: { on: false, n: 25 },
  };

  window.QLP.builder = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("SPL Builder", "Build a security query from modular blocks",
      '<span class="small faint">press <span class="kbd">b</span> anywhere to jump here</span>') +
      '<div class="builder">' +
      '<div><div class="block-stack" id="b-stack"></div>' +
      '<div class="card" style="padding:12px;margin-top:12px">' +
      '<div class="flex-between" style="margin-bottom:8px"><span class="card-title small">' + QL.icon("terminal") + " Generated SPL</span>" +
      '<button class="btn btn-sm btn-primary" id="b-run">' + QL.icon("play") + " Preview Results</button></div>" +
      '<div class="spl-preview" id="b-spl"></div></div></div>' +
      '<div class="card card-flush" id="b-preview">' +
      QL.emptyState({ icon: "blocks", title: "Preview", sub: "Assemble blocks, then run the query." }) +
      "</div></div>";

    renderBlocks();
  };

  function loadMeta() {
    if (S.fieldsCache) return Promise.resolve(S.fieldsCache);
    return api("/spl/fields").then(function (d) {
      S.fieldsCache = d.fields || [];
      return S.fieldsCache;
    }).catch(function () {
      S.fieldsCache = ["index", "source", "host", "user", "severity", "event_type", "source_ip", "destination_ip", "process", "message", "outcome"];
      return S.fieldsCache;
    });
  }

  function timeOpts(current) {
    var opts = ["", "15m", "1h", "6h", "24h", "7d", "30d"];
    return opts.map(function (v) {
      var label = v || "any";
      return "<option value='" + v + "'" + (v === current ? " selected" : "") + ">" + label + "</option>";
    }).join("");
  }

  function renderBlocks() {
    var stack = $("#b-stack");
    var fieldsHtml = B.fields.map(function (f, i) {
      return '<div class="qblock-row" data-fi="' + i + '">' +
        '<input class="input input-mono b-field" placeholder="field" value="' + QL.esc(f.field) + '" list="b-fieldlist">' +
        '<select class="select b-op">' + ["=", "!=", "<", "<=", ">", ">="].map(function (o) {
          return '<option value="' + o + '"' + (o === f.op ? " selected" : "") + ">" + o + "</option>";
        }).join("") + "</select>" +
        '<input class="input input-mono b-val" placeholder="value" value="' + QL.esc(f.value) + '">' +
        '<button class="qblock-remove" data-rm="' + i + '" aria-label="Remove condition">' + QL.icon("x") + "</button>" +
        "</div>";
    }).join("");

    stack.innerHTML =
      '<div class="qblock qblock-search">' +
      '<div class="qblock-header"><span class="qblock-title">' + QL.icon("search") + " Search</span>" +
      '<button class="qblock-remove" data-add-field aria-label="Add condition">' + QL.icon("plus") + "</button></div>" +
      (fieldsHtml || '<div class="small faint" style="margin-bottom:8px">No conditions yet — all events match.</div>') +
      '<datalist id="b-fieldlist"></datalist>' +
      "</div>" +
      '<div class="qblock qblock-time">' +
      '<div class="qblock-header"><span class="qblock-title">' + QL.icon("clock") + " Time Range</span></div>" +
      '<div class="qblock-row" style="grid-template-columns:1fr 1fr">' +
      '<select class="select b-earliest" aria-label="Earliest">' + timeOpts(B.time.earliest) + "</select>" +
      '<select class="select b-latest" aria-label="Latest">' + timeOpts(B.time.latest) + "</select>" +
      "</div></div>" +
      (B.stats.on ? statsBlock() : '<button class="qblock-add" id="b-add-stats">' + QL.icon("plus") + " Add stats block</button>") +
      (B.sort.on ? sortBlock() : '<button class="qblock-add" id="b-add-sort">' + QL.icon("plus") + " Add sort block</button>") +
      (B.head.on ? headBlock() : '<button class="qblock-add" id="b-add-head">' + QL.icon("plus") + " Add limit block</button>") +
      '<button class="btn btn-ghost btn-sm" id="b-clear" style="margin-left:auto"' + (emptyQuery() ? " hidden" : "") + ">" + QL.icon("trash") + " Clear all blocks</button>";

    loadMeta().then(function (fields) {
      var dl = $("#b-fieldlist");
      if (dl) dl.innerHTML = fields.map(function (f) { return "<option value='" + QL.esc(f) + "'></option>"; }).join("");
    });

    $$(".qblock-row[data-fi]", stack).forEach(function (row) {
      var i = Number(row.dataset.fi);
      row.querySelector(".b-field").addEventListener("input", function (e) { B.fields[i].field = e.target.value; buildSPL(); });
      row.querySelector(".b-val").addEventListener("input", function (e) { B.fields[i].value = e.target.value; buildSPL(); });
      row.querySelector(".b-op").addEventListener("change", function (e) { B.fields[i].op = e.target.value; buildSPL(); });
    });
    var addField = stack.querySelector("[data-add-field]");
    if (addField) addField.addEventListener("click", function () {
      B.fields.push({ field: "", op: "=", value: "" });
      renderBlocks();
    });
    $$("[data-rm]", stack).forEach(function (b) {
      b.addEventListener("click", function () {
        B.fields.splice(Number(b.dataset.rm), 1);
        renderBlocks();
      });
    });
    var earliest = $(".b-earliest", stack), latest = $(".b-latest", stack);
    if (earliest) earliest.addEventListener("change", function () { B.time.earliest = earliest.value; buildSPL(); });
    if (latest) latest.addEventListener("change", function () { B.time.latest = latest.value; buildSPL(); });

    var addStats = $("#b-add-stats");
    if (addStats) addStats.addEventListener("click", function () { B.stats.on = true; renderBlocks(); });
    var addSort = $("#b-add-sort");
    if (addSort) addSort.addEventListener("click", function () { B.sort.on = true; B.sort.field = B.sort.field || "timestamp"; renderBlocks(); });
    var addHead = $("#b-add-head");
    if (addHead) addHead.addEventListener("click", function () { B.head.on = true; renderBlocks(); });
    var clear = $("#b-clear");
    if (clear) clear.addEventListener("click", function () {
      B.fields = []; B.stats.on = B.sort.on = B.head.on = false;
      B.time = { earliest: "24h", latest: "now" };
      renderBlocks();
    });

    wireStatsBlock(stack);
    wireSortBlock(stack);
    wireHeadBlock(stack);
    buildSPL();
  }

  function statsBlock() {
    return '<div class="qblock qblock-stats"><div class="qblock-header">' +
      '<span class="qblock-title">' + QL.icon("filter") + " Stats</span>" +
      '<button class="qblock-remove" id="b-rm-stats">' + QL.icon("x") + "</button></div>" +
      '<div class="qblock-row" style="grid-template-columns:110px 1fr 1fr">' +
      '<select class="select b-stats-fn" aria-label="Aggregation">' + ["count", "sum", "avg", "min", "max", "dc"].map(function (fn) {
        return '<option value="' + fn + '"' + (fn === B.stats.fn ? " selected" : "") + ">" + fn + "</option>";
      }).join("") + "</select>" +
      '<input class="input input-mono b-stats-field" placeholder="field (blank for count)" value="' + QL.esc(B.stats.field) + '">' +
      '<input class="input input-mono b-stats-alias" placeholder="alias" value="' + QL.esc(B.stats.alias) + '"></div>' +
      '<div class="qblock-row" style="grid-template-columns:1fr">' +
      '<input class="input input-mono b-stats-by" placeholder="group by field (comma-separated)" value="' + QL.esc(B.stats.by) + '"></div>' +
      "</div>";
  }
  function wireStatsBlock(stack) {
    var rm = $("#b-rm-stats");
    if (rm) rm.addEventListener("click", function () { B.stats.on = false; renderBlocks(); });
    var fn = $(".b-stats-fn", stack), fld = $(".b-stats-field", stack), al = $(".b-stats-alias", stack), by = $(".b-stats-by", stack);
    if (fn) fn.addEventListener("change", function () { B.stats.fn = fn.value; buildSPL(); });
    if (fld) fld.addEventListener("input", function () { B.stats.field = fld.value.trim(); buildSPL(); });
    if (al) al.addEventListener("input", function () { B.stats.alias = al.value.trim(); buildSPL(); });
    if (by) by.addEventListener("input", function () { B.stats.by = by.value.trim(); buildSPL(); });
  }
  function sortBlock() {
    return '<div class="qblock qblock-sort"><div class="qblock-header">' +
      '<span class="qblock-title">' + QL.icon("timeline") + " Sort</span>" +
      '<button class="qblock-remove" id="b-rm-sort">' + QL.icon("x") + "</button></div>" +
      '<div class="qblock-row" style="grid-template-columns:1fr 130px">' +
      '<input class="input input-mono b-sort-field" placeholder="field" value="' + QL.esc(B.sort.field) + '">' +
      '<select class="select b-sort-dir" aria-label="Direction"><option value="desc"' + (B.sort.desc ? " selected" : "") + ">descending</option>" +
      '<option value="asc"' + (!B.sort.desc ? " selected" : "") + ">ascending</option></select></div></div>";
  }
  function wireSortBlock(stack) {
    var rm = $("#b-rm-sort");
    if (rm) rm.addEventListener("click", function () { B.sort.on = false; renderBlocks(); });
    var f = $(".b-sort-field", stack), d = $(".b-sort-dir", stack);
    if (f) f.addEventListener("input", function () { B.sort.field = f.value.trim(); buildSPL(); });
    if (d) d.addEventListener("change", function () { B.sort.desc = d.value === "desc"; buildSPL(); });
  }
  function headBlock() {
    return '<div class="qblock qblock-head"><div class="qblock-header">' +
      '<span class="qblock-title">' + QL.icon("layers") + " Limit</span>" +
      '<button class="qblock-remove" id="b-rm-head">' + QL.icon("x") + "</button></div>" +
      '<div class="qblock-row" style="grid-template-columns:1fr"><input class="input input-mono b-head-n" type="number" min="1" value="' + B.head.n + '"></div></div>';
  }
  function wireHeadBlock(stack) {
    var rm = $("#b-rm-head");
    if (rm) rm.addEventListener("click", function () { B.head.on = false; renderBlocks(); });
    var n = $(".b-head-n", stack);
    if (n) n.addEventListener("input", function () { B.head.n = Number(n.value) || 25; buildSPL(); });
  }

  function emptyQuery() {
    return !B.fields.length && !B.stats.on && !B.sort.on && !B.head.on;
  }

  function buildSPL() {
    var parts = [];
    var f = B.fields.filter(function (x) { return x.field && x.value !== ""; });
    if (f.length) {
      parts.push(f.map(function (x) {
        return x.field + " " + x.op + " " + (/[",\s]/.test(x.value) ? '"' + x.value.replace(/"/g, "'") + '"' : x.value);
      }).join(" AND "));
    }
    if (B.stats.on && B.stats.fn) {
      var agg = B.stats.fn === "count" ? "count()" : B.stats.fn + "(" + (B.stats.field || "*") + ")";
      if (B.stats.alias) agg += " as " + B.stats.alias;
      parts.push("stats " + agg + (B.stats.by ? " by " + B.stats.by : ""));
    }
    if (B.sort.on && B.sort.field) parts.push("sort " + (B.sort.desc ? "-" : "") + B.sort.field);
    if (B.head.on) parts.push("head " + B.head.n);
    var spl = parts.length ? "search " + parts.join(" | ") : "search";
    var el = $("#b-spl");
    if (el) el.innerHTML = spl.split(" | ").map(function (p, i) {
      return i === 0 ? QL.esc(p) : '<span class="pipe">| </span>' + QL.esc(p);
    }).join(" ");
    return spl;
  }

  function initBuilderRun() {
    var btn = $("#b-run");
    if (btn) btn.addEventListener("click", runBuilder);
  }

  function runBuilder() {
    var spl = buildSPL();
    var box = $("#b-preview");
    box.innerHTML = QL.loading("Running query…");
    var body = { query: spl, limit: B.head.on ? B.head.n : 50 };
    if (B.time.earliest) body.earliest = B.time.earliest;
    if (B.time.latest) body.latest = B.time.latest;
    api("/spl/preview", { method: "POST", body: body }).then(function (d) {
      if (!d.ok) {
        box.innerHTML = QL.emptyState({ icon: "warning", title: "Query failed", sub: (d.error && d.error.message) || "invalid query" });
        return;
      }
      var cols = d.fields || [];
      var rows = d.results || [];
      box.innerHTML =
        '<div class="card-header"><span class="card-title">' + QL.icon("eye") + " Preview Results</span>" +
        '<span class="small faint">' + d.count + " matching event" + (d.count === 1 ? "" : "s") + " · " + Math.round(d.execution_ms || 0) + " ms</span></div>" +
        '<div class="card-body card-flush">' +
        (rows.length ? resultTable(cols, rows, 50) : '<div class="empty" style="padding:28px"><p>No matching events.</p></div>') +
        "</div>";
    }).catch(function (e) {
      box.innerHTML = QL.emptyState({ icon: "warning", title: "Preview failed", sub: e.message });
    });
  }

  /* re-bind the run button after page re-render */
  var _builderHook = window.QLP.builder;
  window.QLP.builder = function () {
    _builderHook();
    setTimeout(initBuilderRun, 0);
  };

  /* ═══ Detections ═══════════════════════════════════════════ */
  window.QLP.detections = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Detections", "Detection rules that turn raw events into findings",
      '<button class="btn btn-primary" id="d-new">' + QL.icon("plus") + " New Rule</button>") +
      '<div class="card card-flush" id="d-table">' + QL.loading("Loading…") + "</div>";

    load();
    function load() {
      api("/detections").then(function (rules) {
        var list = rules || [];
        if (!list.length) {
          $("#d-table").innerHTML = QL.emptyState({ icon: "shieldAlert", title: "No detection rules", sub: "Create your first rule to start generating findings." });
          return;
        }
        $("#d-table").innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Rule</th><th>Severity</th><th>Query</th><th>Enabled</th><th>Actions</th></tr></thead><tbody>" +
          list.map(function (r) {
            return "<tr>" +
              '<td class="cell-title">' + QL.esc(r.name) + "</td>" +
              "<td>" + QL.sevBadge(r.severity) + "</td>" +
              '<td class="cell-mono" style="max-width:380px"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;max-width:100%" title="' + QL.esc(r.query) + '">' + QL.esc(r.query) + "</span></td>" +
              "<td>" + (r.enabled
                ? '<span class="badge badge-sev success"><span class="dot"></span>On</span>'
                : '<span class="badge badge-sev muted"><span class="dot"></span>Off</span>') + "</td>" +
              '<td><div class="flex" style="gap:6px">' +
              '<button class="btn btn-sm" data-run="' + r.id + '">' + QL.icon("play") + " Run</button>" +
              '<button class="btn btn-sm" data-tgl="' + r.id + '" data-on="' + (r.enabled ? "1" : "0") + '">' + (r.enabled ? "Disable" : "Enable") + "</button>" +
              '<button class="btn btn-sm" data-del="' + r.id + '" aria-label="Delete rule" data-tip="Delete">' + QL.icon("trash") + "</button>" +
              "</div></td></tr>";
          }).join("") + "</tbody></table></div>";

        $$("[data-run]").forEach(function (b) {
          b.addEventListener("click", function () {
            api("/detections/" + b.dataset.run + "/exec", { method: "POST" }).then(function (res) {
              var m = res && (res.matched != null ? res.matched : (res.matched_count != null ? res.matched_count : "done"));
              QL.toast("Rule executed · " + JSON.stringify(m));
              load();
            }).catch(function (e) { QL.toast(e.message, "error"); });
          });
        });
        $$("[data-tgl]").forEach(function (b) {
          b.addEventListener("click", function () {
            var on = b.dataset.on !== "1";
            api("/detections/" + b.dataset.tgl, { method: "PUT", body: { enabled: on } }).then(function () {
              QL.toast(on ? "Rule enabled" : "Rule disabled");
              load();
            }).catch(function (e) { QL.toast(e.message, "error"); });
          });
        });
        $$("[data-del]").forEach(function (b) {
          b.addEventListener("click", function () {
            QL.confirmDialog("Delete rule?", "The detection rule will be removed. Findings already created are kept.", {
              danger: true, okLabel: "Delete",
              onOk: function () {
                api("/detections/" + b.dataset.del, { method: "DELETE" }).then(function () {
                  QL.toast("Rule deleted");
                  load();
                }).catch(function (e) { QL.toast(e.message, "error"); });
              },
            });
          });
        });
      }).catch(function (e) {
        $("#d-table").innerHTML = QL.emptyState({ icon: "warning", title: "Failed to load detections", sub: e.message });
      });
    }

    $("#d-new").addEventListener("click", function () {
      var close = QL.modal({
        title: "New detection rule",
        body:
          '<div class="field"><label for="dr-name">Name</label><input class="input" id="dr-name" placeholder="e.g. Repeated auth failures"></div>' +
          '<div class="field"><label for="dr-query">Query (SPL)</label><textarea class="textarea input-mono" id="dr-query" placeholder="index=auth outcome=failure | stats count by user | where count > 5"></textarea></div>' +
          '<div class="field"><label for="dr-sev">Severity</label><select class="select" id="dr-sev">' +
          ["critical", "high", "medium", "low"].map(function (s) { return "<option>" + s + "</option>"; }).join("") +
          "</select></div>",
        footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>' + QL.icon("plus") + " Create</button>",
      });
      close.el.addEventListener("click", function (e) {
        if (e.target.dataset.x) close();
        if (e.target.dataset.ok) {
          var name = $("#dr-name").value.trim();
          var query = $("#dr-query").value.trim();
          if (!name || !query) { QL.toast("Name and query are required", "error"); return; }
          api("/detections", { method: "POST", body: { name: name, query: query, severity: $("#dr-sev").value } }).then(function () {
            close(); QL.toast("Detection created"); load();
          }).catch(function (er) { QL.toast(er.message, "error"); });
        }
      });
    });
  };

  /* ═══ Risk ═════════════════════════════════════════════════ */
  window.QLP.risk = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Risk", "Accumulated entity risk, with a transparent breakdown",
      '<span class="range-group" id="r-tabs">' +
      ["user", "host", "ip"].map(function (t) {
        return '<button class="range-pill' + (t === S.riskType ? " active" : "") + '" data-rt="' + t + '">' + t + "s</button>";
      }).join("") + "</span>") +
      '<div class="card card-flush" id="r-table">' + QL.loading("Scoring entities…") + "</div>";

    load();
    function load() {
      api("/risk/entities?type=" + S.riskType + "&limit=50").then(function (d) {
        var list = d.entities || [];
        if (!list.length) {
          $("#r-table").innerHTML = QL.emptyState({ icon: "gauge", title: "No risk recorded", sub: "Risk accumulates as findings open against " + S.riskType + "s." });
          return;
        }
        $("#r-table").innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Entity</th><th>Type</th><th>Risk</th><th style='width:200px'>Meter</th><th>Findings</th><th>Updated</th></tr></thead><tbody>" +
          list.map(function (e) {
            return '<tr class="clickable" data-entity="' + QL.esc(e.type) + "/" + QL.esc(e.value) + '">' +
              '<td class="cell-title flex" style="gap:8px">' + QL.icon(QL.entityIcon(e.type)) + QL.esc(e.value) + "</td>" +
              '<td class="cell-muted">' + QL.esc(e.type) + "</td>" +
              "<td>" + QL.riskBadge(e.risk_score, false) + "</td>" +
              "<td>" + QL.riskBar(e.risk_score, 150) + "</td>" +
              '<td class="cell-mono">' + (e.findings || 0) + "</td>" +
              '<td class="cell-muted nowrap">' + QL.fmtAgo(e.updated_at) + "</td></tr>";
          }).join("") + "</tbody></table></div>";
        $$("#r-table tr[data-entity]").forEach(function (tr) {
          tr.addEventListener("click", function () {
            var parts = tr.dataset.entity.split("/");
            location.hash = "#/entity/" + encodeURIComponent(parts[0]) + "/" + encodeURIComponent(parts[1]);
          });
        });
      }).catch(function (e) {
        $("#r-table").innerHTML = QL.emptyState({ icon: "warning", title: e.message });
      });
    }
    $$("#r-tabs .range-pill").forEach(function (b) {
      b.addEventListener("click", function () {
        S.riskType = b.dataset.rt;
        $$("#r-tabs .range-pill").forEach(function (x) { x.classList.remove("active"); });
        b.classList.add("active");
        load();
      });
    });
  };

  /* ═══ Entities ═════════════════════════════════════════════ */
  window.QLP.entities = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Entities", "Correlated security entities and their risk", "") +
      '<div class="card" style="margin-bottom:14px"><div class="card-body"><div class="filter-bar">' +
      QL_.sel("e-type", "Type", [["user", "Users"], ["host", "Hosts"], ["ip", "IPs"]], S.riskType || "user") +
      '<div class="search-box" style="flex:1;min-width:220px"><span class="ic-lead">' + QL.icon("search") + "</span>" +
      '<input class="input input-mono" id="e-value" placeholder="search entity value…"></div>' +
      '<button class="btn btn-primary" id="e-go">' + QL.icon("search") + " Look up</button>" +
      "</div></div></div>" +
      '<div class="card card-flush" id="e-list"></div>';

    load(S.riskType || "user");
    function load(type) {
      S.riskType = type;
      api("/risk/entities?type=" + type + "&limit=50").then(function (d) {
        var list = d.entities || [];
        var el = $("#e-list");
        if (!list.length) {
          el.innerHTML = QL.emptyState({ icon: "entities", title: "No entities found", sub: "Ingest events to see correlated " + type + "s." });
          return;
        }
        el.innerHTML = '<div class="entity-list" style="padding:6px 14px">' + list.map(function (e) {
          return QL_.entityRow(e.type, e.value, e.risk_score, e.findings);
        }).join("") + "</div>";
        QL_.bindEntityRows(el);
      }).catch(function (e) {
        $("#e-list").innerHTML = QL.emptyState({ icon: "warning", title: e.message });
      });
    }
    $("#e-type").addEventListener("change", function (e) { load(e.target.value); });
    $("#e-go").addEventListener("click", go);
    $("#e-value").addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    function go() {
      var v = $("#e-value").value.trim();
      if (v) location.hash = "#/entity/" + encodeURIComponent($("#e-type").value) + "/" + encodeURIComponent(v);
      else load($("#e-type").value);
    }
  };

  /* ═══ Entity detail ════════════════════════════════════════ */
  window.QLP.entity = function (type, value) {
    var page = $("#page");
    type = decodeURIComponent(type || "user");
    value = decodeURIComponent(value || "");
    api("/intel/" + encodeURIComponent(type) + "/" + encodeURIComponent(value)).then(function (d) {
      var ent = d.entity || {};
      var score = d.risk_score || 0;
      var rep = d.reputation || "unknown";
      var repColor = rep === "malicious" ? "var(--ql-sev-critical)" :
        rep === "suspicious" ? "var(--ql-sev-high)" :
        rep === "benign" ? "var(--ql-sev-success)" : "var(--ql-text-muted)";
      page.innerHTML =
        '<div class="flex" style="margin-bottom:12px"><a class="btn btn-ghost btn-sm" href="#/entities">' + QL.icon("arrow-left") + " All entities</a></div>" +
        '<div class="page-header"><div style="min-width:0">' +
        '<div class="flex" style="gap:12px;align-items:center;margin-bottom:6px;flex-wrap:wrap">' +
        '<span class="entity-ic" style="width:46px;height:46px">' + QL.icon(QL.entityIcon(type)) + "</span>" +
        "<div><h1 style='font-size:24px' class='mono'>" + QL.esc(value) + "</h1>" +
        '<div class="small faint">' + QL.esc(type) + " entity</div></div>" +
        '<span class="badge" style="background:var(--ql-surface-2);color:' + repColor + '"><span class="dot"></span>' + QL.esc(rep.toUpperCase()) + "</span>" +
        " " + QL.riskBadge(score) + "</div>" +
        '<div class="page-actions">' +
        '<button class="btn" id="e-create-inv">' + QL.icon("investigate") + " Investigate</button>" +
        "</div></div></div>" +
        '<div class="card" style="margin-bottom:14px"><div class="card-body"><div class="kv-grid">' +
        QL.kv("clock", "First Seen", ent.first_seen ? QL.fmtDateTime(ent.first_seen) : "—") +
        QL.kv("clock", "Last Seen", ent.last_seen ? QL.fmtDateTime(ent.last_seen) : "—") +
        QL.kv("activity", "Observed Events", ent.event_count) +
        QL.kv("gauge", "Risk Score", Math.round(score)) +
        QL.kv("queue", "Open Findings", d.open_findings) +
        "</div></div></div>" +
        '<div class="dash-grid">' +
        '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("entities") + " Relationship Map</div></div>" +
        '<div class="card-body" id="e-graph">' + QL.loading("Mapping…") + "</div></div>" +
        '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("gauge") + " Risk Contributions</div></div>" +
        '<div class="card-body" id="e-contrib"></div></div>' +
        "</div>" +
        '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("queue") + " Related Findings</div></div>" +
        '<div class="card-body card-flush" id="e-findings"></div></div>';

      api("/entities/" + encodeURIComponent(type) + "/" + encodeURIComponent(value)).then(function (det) {
        $("#e-graph").innerHTML = QL_.entityGraphHtml({ type: type, value: value }, det.neighbors || []);
        QL_.bindGraph($("#e-graph"));
        var contribs = det.risk_contributions || [];
        $("#e-contrib").innerHTML = contribs.length
          ? '<div style="display:flex;flex-direction:column;gap:6px">' + contribs.map(function (c) {
              return '<div class="flex-between" style="padding:7px 10px;background:var(--ql-bg-deep);border-radius:8px">' +
                '<span class="small muted">' + QL.esc(c.source_type) + (c.description ? " · " + QL.esc(c.description) : "") + "</span>" +
                '<span class="mono small" style="color:' + QL.riskColor(c.points) + '">+' + c.points + "</span></div>";
            }).join("") + "</div>"
          : QL.emptyState({ icon: "gauge", title: "No contributions", sub: "Risk contributions appear when findings reference this entity." });
        var rel = det.findings || [];
        var el = $("#e-findings");
        if (!rel.length) { el.innerHTML = QL.emptyState({ icon: "queue", title: "No related findings" }); return; }
        el.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr>' +
          "<th>Severity</th><th>Finding</th><th>Risk</th><th>Status</th><th>Last Seen</th></tr></thead><tbody>" +
          rel.map(function (f) {
            return '<tr class="clickable" data-f="' + f.id + '"><td>' + QL.sevBadge(f.severity) + "</td>" +
              '<td class="cell-title">' + QL.esc(f.title) + "</td>" +
              "<td>" + QL.riskBadge(f.risk_score, false) + "</td>" +
              "<td>" + QL.statusBadge(f.status) + "</td>" +
              '<td class="cell-muted">' + QL.fmtAgo(f.last_seen) + "</td></tr>";
          }).join("") + "</tbody></table></div>";
        $$("#e-findings tr[data-f]").forEach(function (tr) {
          tr.addEventListener("click", function () { location.hash = "#/finding/" + tr.dataset.f; });
        });
      }).catch(function () {
        $("#e-graph").innerHTML = QL.emptyState({ icon: "entities", title: "No neighbors found" });
      });

      $("#e-create-inv").addEventListener("click", function () {
        var close = QL.modal({
          title: "Investigate " + value,
          body: '<div class="field"><label for="ei-title">Investigation title</label><input class="input" id="ei-title" value="Investigate ' + QL.esc(value) + '"></div>' +
            '<div class="field"><label for="ei-sev">Severity</label><select class="select" id="ei-sev"><option>critical</option><option>high</option><option selected>medium</option><option>low</option></select></div>',
          footer: '<button class="btn" data-x>Cancel</button><button class="btn btn-primary" data-ok>Create</button>',
        });
        close.el.addEventListener("click", function (e) {
          if (e.target.dataset.x) close();
          if (e.target.dataset.ok) {
            api("/investigations", {
              method: "POST",
              body: {
                title: $("#ei-title").value.trim() || "Investigate " + value,
                severity: $("#ei-sev").value,
                description: "Investigation started from entity " + type + ":" + value,
              },
            }).then(function (inv) {
              return api("/investigations/" + inv.id, {
                method: "PATCH",
                body: { add_entities: [{ type: type, value: value }] },
              }).then(function () {
                close();
                location.hash = "#/investigation/" + inv.id;
              });
            }).catch(function (er) { QL.toast(er.message, "error"); });
          }
        });
      });
    }).catch(function (e) {
      page.innerHTML = QL.emptyState({ icon: "warning", title: "Entity not found", sub: e.message,
        action: '<a class="btn" href="#/entities">Back to entities</a>' });
    });
  };

  /* ═══ Threat Intelligence / MITRE ══════════════════════════ */
  window.QLP.mitre = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Threat Intelligence", "MITRE ATT&CK techniques active in your environment", "") +
      '<div class="card" style="margin-bottom:14px"><div class="card-header">' +
      '<div><div class="card-title">' + QL.icon("crosshair") + " Active Techniques</div>" +
      '<div class="card-sub">Derived from open findings</div></div></div>' +
      '<div class="card-body" id="m-active">' + QL.loading("Loading…") + "</div></div>" +
      '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("layers") + " Tactic Coverage</div></div>" +
      '<div class="card-body" id="m-tactics"></div></div>';

    Promise.all([
      api("/mitre/active").catch(function () { return []; }),
      api("/mitre/tactics").catch(function () { return []; }),
      api("/mitre/techniques").catch(function () { return []; }),
    ]).then(function (res) {
      var active = res[0] || [];
      var tactics = res[1] || [];
      var catalog = res[2] || [];
      var cat = {};
      catalog.forEach(function (t) { if (t.id) cat[t.id] = t; });

      var el = $("#m-active");
      if (!active.length) {
        el.innerHTML = QL.emptyState({ icon: "crosshair", title: "No active techniques", sub: "Open findings that reference MITRE techniques will appear here." });
      } else {
        el.innerHTML = '<div class="mitre-list">' + active.map(function (a) {
          var meta = cat[a.technique] || {};
          return '<div class="mitre-row">' +
            '<span class="mitre-code">' + QL.esc(a.technique) + "</span>" +
            '<div><div class="mitre-name">' + QL.esc(a.technique_name || meta.name || a.technique) + "</div>" +
            '<div class="mitre-tactic">' + QL.esc(a.tactic_name || meta.tactic_name || a.tactic) + "</div></div>" +
            '<span class="badge badge-sev high"><span class="dot"></span>' + a.count + " finding" + (a.count === 1 ? "" : "s") + "</span>" +
            "</div>";
        }).join("") + "</div>";
      }

      var tEl = $("#m-tactics");
      if (!tactics.length) { tEl.innerHTML = QL.emptyState({ icon: "layers", title: "No tactic data" }); return; }
      var byTactic = {};
      active.forEach(function (a) { byTactic[a.tactic] = (byTactic[a.tactic] || 0) + a.count; });
      tEl.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr><th>Tactic</th><th>Active Techniques</th></tr></thead><tbody>' +
        tactics.map(function (t) {
          var id = t.id || t.tactic;
          var n = byTactic[id] || 0;
          return "<tr><td>" +
            '<span class="flex" style="gap:8px">' +
            '<i style="width:10px;height:10px;border-radius:3px;display:inline-block;background:' +
            (n ? "var(--ql-sev-high)" : "var(--ql-surface-3)") + '"></i>' +
            QL.esc(t.name || id) + "</span></td>" +
            '<td class="cell-mono">' + (n || "—") + "</td></tr>";
        }).join("") + "</tbody></table></div>";
    });
  };

  /* ═══ Settings ═════════════════════════════════════════════ */
  window.QLP.settings = function () {
    var page = $("#page");
    page.innerHTML = QL_.pageHeader("Settings", "Workspace, security and system configuration", "") +
      '<div class="dash-grid">' +
      '<div class="card"><div class="card-body" style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">' +
      '<div aria-hidden="true">' + QL.dragon({ size: 92 }) + "</div>" +
      '<div><div style="font-size:19px;font-weight:700">Quetzalog</div>' +
      '<div class="small muted">SEE MORE. SOLVE FASTER. — Small Dragon. Big Insights.</div>' +
      '<div class="small faint" style="margin-top:6px" id="set-ver"></div></div></div></div>' +
      '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("settings") + " Preferences</div></div>" +
      '<div class="card-body"><div class="flex-between" style="padding:8px 0">' +
      '<div><b class="small">Interface theme</b><div class="small faint">Dark is the SOC default; light for the office.</div></div>' +
      '<button class="btn" id="theme-toggle" data-theme-toggle></button></div></div></div></div>' +
       '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("database") + " Ingestion</div></div>" +
       '<div class="card-body" id="set-ingest"></div></div>' +
       '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("spark") + " AI Analyst</div></div>" +
       '<div class="card-body" id="set-ai">' + QL.loading("Loading…") + "</div></div>" +
       '<div class="card"><div class="card-header"><div class="card-title">' + QL.icon("users") + " Users</div></div>" +
      '<div class="card-body card-flush" id="set-users"></div></div>' +
      "</div>" +
      '<div class="card" style="margin-top:14px"><div class="card-header"><div class="card-title">' + QL.icon("terminal") + " Audit Log</div></div>" +
      '<div class="card-body card-flush" id="set-audit">' + QL.loading("Loading…") + "</div></div>";

    api("/health").then(function (h) {
      var v = $("#set-ver");
      if (v) v.textContent = "version " + (h.version || "dev") + " · uptime " + fmtUptime(h.uptime);
    }).catch(function () {});

    var themeBtn = $("#theme-toggle");
    if (themeBtn) themeBtn.addEventListener("click", QL_.toggleTheme);
    QL_.applyTheme(document.documentElement.getAttribute("data-theme"));

    $("#set-ingest").innerHTML =
      '<div style="display:flex;flex-direction:column;gap:10px">' +
      [
        ["JSON HTTP", "Active", "POST /api/v1/events · main port", "success"],
        ["Syslog (TCP/UDP)", "Active", "RFC 5424 & BSD · 1514 / 514", "success"],
        ["Splunk HEC", "Token-gated", "POST /api/v1/json · ingest-only tokens", "info"],
        ["OpenTelemetry", "OTLP", "gRPC 4317 · HTTP 4318 (if enabled)", "info"],
        ["File Ingestion", "Config", "yaml-driven tail sources", "info"],
      ].map(function (r) {
        return '<div class="flex-between" style="padding:6px 0;border-bottom:1px solid var(--ql-border-soft)">' +
          '<span class="flex" style="gap:10px"><b class="small">' + r[0] + '</b><span class="small faint">' + r[2] + "</span></span>" +
          '<span class="badge badge-sev ' + (r[3] === "success" ? "success" : "info") + '"><span class="dot"></span>' + r[1] + "</span></div>";
      }).join("") + "</div>";

    loadUsers();
    loadAudit();
    loadAI();

    function loadAI() {
      api("/settings/ai-analyst").then(function (c) {
        var el = $("#set-ai");
        if (!el) return;
        el.innerHTML =
          '<div class="flex-between" style="padding:4px 0 12px;border-bottom:1px solid var(--ql-border-soft)">' +
          '<div class="small muted">' + QL.icon("spark") + " " +
          "The AI Analyst turns findings into structured, evidence-based analyses with a recommended next step. " +
          "It never executes anything — a human approves or dismisses every recommendation.</div>" +
          '<label class="small flex" style="gap:8px;cursor:pointer;align-items:center">' +
          '<input type="checkbox" id="ai-enabled"' + (c.enabled ? " checked" : "") + "> Automatic analysis</label></div>" +
          '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;padding:12px 0">' +
          '<div class="field"><label>Provider</label><select class="select" id="ai-provider">' +
          ["openai-compatible", "ollama", "opencode"].map(function (p) {
            return '<option value="' + p + '"' + (c.provider === p ? " selected" : "") + ">" + p + "</option>";
          }).join("") + "</select></div>" +
          '<div class="field" style="grid-column:1/-1"><label>Endpoint</label>' +
          '<input class="input input-mono" id="ai-endpoint" placeholder="http://10.0.0.1:8000 (vLLM), http://192.168.1.50:11434 (Ollama) — with or without /v1" value="' + QL.esc(c.endpoint || "") + '"></div>' +
          '<div class="field"><label>API key / server password</label>' +
          '<input class="input input-mono" id="ai-key" type="password" placeholder="' + (c.api_key_set ? "•••••••• (set)" : "none") + '" autocomplete="off">' +
          '<div class="field-hint">Leave blank to keep the current key. Write $CLEAR to remove it. Never returned by the API.</div></div>' +
          '<div class="field"><label>Username (OpenCode only)</label>' +
          '<input class="input" id="ai-username" value="' + QL.esc(c.username || "") + '" placeholder="opencode"></div>' +
          '<div class="field"><label>Model</label>' +
          '<div class="flex" style="gap:6px">' +
          '<input class="input input-mono" id="ai-model" placeholder="qwen3.8 or opencode/qwen3.8" value="' + QL.esc(c.model || "") + '" style="flex:1;min-width:0">' +
          '<button class="btn btn-sm" id="ai-models" title="Fetch available models">' + QL.icon("download") + "</button></div></div>" +
          '<div class="field"><label>Minimum severity (auto)</label><select class="select" id="ai-sev">' +
          ["critical", "high", "medium", "low"].map(function (s) {
            return '<option value="' + s + '"' + (c.minimum_severity === s ? " selected" : "") + ">" + s + "</option>";
          }).join("") + "</select>" +
          '<div class="field-hint">Automatic analysis only; manual “Analyze with AI” bypasses this.</div></div>' +
          '<div class="field"><label>Max requests / minute</label>' +
          '<input class="input input-mono" id="ai-rpm" type="number" min="1" value="' + (c.max_requests_per_minute || 10) + '"></div>' +
          '<div class="field"><label>Timeout (seconds)</label>' +
          '<input class="input input-mono" id="ai-timeout" type="number" min="5" value="' + (c.timeout_seconds || 300) + '">' +
          '<div class="field-hint">Per model call. Local models are slow — with a full context a quantized model can take 2-4 minutes.</div></div>' +
          '<div class="field"><label>Max context events</label>' +
          '<input class="input input-mono" id="ai-events" type="number" min="1" value="' + (c.max_context_events || 100) + '"></div>' +
          '<div class="field"><label>Retries</label>' +
          '<input class="input input-mono" id="ai-retry" type="number" min="0" max="5" value="' + (c.retry_count || 1) + '"></div>' +
          "</div>" +
          '<div class="flex" style="gap:8px;flex-wrap:wrap;padding-top:4px">' +
          '<button class="btn btn-primary" id="ai-save">' + QL.icon("save") + " Save</button>" +
          '<button class="btn" id="ai-test">' + QL.icon("play") + " Test connection</button>" +
          (c.persisted ? '<span class="small faint" style="align-self:center">Saved to the config file</span>'
                     : '<span class="small faint" style="align-self:center">In-memory only — start quetzalog with --config to persist</span>') +
          "</div>" +
          '<div id="ai-test-result" style="margin-top:10px"></div>';

        function body() {
          return {
            enabled: $("#ai-enabled").checked,
            provider: $("#ai-provider").value,
            endpoint: $("#ai-endpoint").value.trim(),
            api_key: $("#ai-key").value,
            username: $("#ai-username").value.trim(),
            model: $("#ai-model").value.trim(),
            minimum_severity: $("#ai-sev").value,
            max_requests_per_minute: Number($("#ai-rpm").value) || 10,
            timeout_seconds: Number($("#ai-timeout").value) || 300,
            max_context_events: Number($("#ai-events").value) || 100,
            retry_count: Number($("#ai-retry").value) || 0,
          };
        }

        $("#ai-save").addEventListener("click", function () {
          var b = body();
          if (!b.endpoint) { QL.toast("Endpoint is required", "error"); return; }
          if (b.enabled && !b.model) { QL.toast("Model is required when automatic analysis is enabled", "error"); return; }
          api("/settings/ai-analyst", { method: "PUT", body: b }).then(function (u) {
            QL.toast("AI Analyst configuration saved");
            loadAI();
          }).catch(function (e) { QL.toast(e.message, "error"); });
        });

        // Test / Load-models act on what is in the form, not on the last
        // saved config — so save the current values first (silently).
        function saveForm(cb) {
          var b = body();
          if (!b.endpoint) {
            QL.toast("Endpoint is required — enter it in the form above first.", "error");
            return;
          }
          api("/settings/ai-analyst", { method: "PUT", body: b }).then(function (u) {
            $("#ai-key").placeholder = u.api_key_set ? "•••••••• (set)" : "none";
            cb();
          }).catch(function (e) { QL.toast(e.message || "Could not save settings", "error"); });
        }

        $("#ai-test").addEventListener("click", function () {
          saveForm(function () {
            var out = $("#ai-test-result");
            out.innerHTML = '<div class="small muted flex" style="gap:8px">' + QL.loading("Probing the endpoint…") + "</div>";
            api("/settings/ai-analyst/test", { method: "POST" }).then(function (r) {
              out.innerHTML = r.ok
                ? '<div class="ai-decision approved">' + QL.icon("check") + "<span>Connected to <b>" + QL.esc(r.provider || "") + "</b>" +
                  (r.model ? " · model <span class='mono'>" + QL.esc(r.model) + "</span>" : "") +
                  (r.latency ? " · " + QL.esc(r.latency) : "") + " — " + QL.esc(r.detail || "ok") + "</span></div>"
                : '<div class="ai-decision dismissed">' + QL.icon("x") + "<span>" + QL.esc(r.detail || "Connection failed") + "</span></div>";
            }).catch(function (e) {
              out.innerHTML = '<div class="ai-decision dismissed">' + QL.icon("x") + "<span>" + QL.esc(e.message) + "</span></div>";
            });
          });
        });

        $("#ai-models").addEventListener("click", function () {
          saveForm(function () {
          api("/settings/ai-analyst/models").then(function (m) {
            if (!m.supported) {
              QL.toast("Could not list models" + (m.detail ? ": " + m.detail : "") + " — type the model name manually", "error");
              return;
            }
            var list = m.models || [];
            if (!list.length) { QL.toast("No models found"); return; }
            var close = QL.modal({
              title: "Available models",
              body: '<div style="display:flex;flex-direction:column;gap:6px;max-height:340px;overflow:auto">' +
                list.map(function (id) {
                  return '<button class="btn btn-ghost btn-sm" data-m="' + QL.esc(id) + '" style="text-align:left;font-family:var(--ql-font-mono)">' + QL.esc(id) + "</button>";
                }).join("") + "</div>",
              footer: "",
            });
            close.el.addEventListener("click", function (e) {
              var b = e.target.closest("[data-m]");
              if (b) { $("#ai-model").value = b.dataset.m; close(); }
            });
          }).catch(function (e) { QL.toast(e.message, "error"); });
          });
        });
      }).catch(function (e) {
        var el = $("#set-ai");
        if (el) el.innerHTML = QL.emptyState({ icon: "spark", title: "AI Analyst unavailable", sub: e.message });
      });
    }

    function loadUsers() {
      api("/users").then(function (users) {
        var el = $("#set-users");
        el.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr><th>User</th><th>Role</th><th>Status</th></tr></thead><tbody>' +
          (users || []).map(function (u) {
            return "<tr><td class='cell-title flex' style='gap:8px'>" +
              '<span class="avatar" style="width:24px;height:24px;font-size:10px">' + QL.esc((u.username || "?").slice(0, 2).toUpperCase()) + "</span>" +
              QL.esc(u.username) + "</td>" +
              '<td class="cell-muted">' + QL.esc(u.role || "") + "</td>" +
              "<td>" + (u.enabled
                ? '<span class="badge badge-sev success"><span class="dot"></span>Active</span>'
                : '<span class="badge badge-sev muted"><span class="dot"></span>Disabled</span>') + "</td></tr>";
          }).join("") + "</tbody></table></div>";
      }).catch(function (e) {
        $("#set-users").innerHTML = QL.emptyState({ icon: "users", title: "User management unavailable", sub: e.message });
      });
    }

    function loadAudit() {
      api("/audit?limit=25").then(function (entries) {
        var el = $("#set-audit");
        if (!entries || !entries.length) { el.innerHTML = QL.emptyState({ icon: "terminal", title: "No audit entries" }); return; }
        el.innerHTML = '<div class="table-wrap"><table class="ql-table"><thead><tr><th>When</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>' +
          entries.map(function (a) {
            return "<tr>" +
              '<td class="cell-muted nowrap">' + (a.created_at ? QL.fmtDateTime(a.created_at) : "") + "</td>" +
              "<td>" + QL.esc(a.username || a.user || "—") + "</td>" +
              '<td class="cell-mono">' + QL.esc(a.action || "") + "</td>" +
              '<td class="cell-mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + QL.esc(a.target || "") + "</td>" +
              '<td class="small muted" style="max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + QL.esc(a.detail || "") + "</td></tr>";
          }).join("") + "</tbody></table></div>";
      }).catch(function (e) {
        $("#set-audit").innerHTML = QL.emptyState({ icon: "terminal", title: "Audit log unavailable", sub: e.message });
      });
    }
  };

  /* ═══ 404 ══════════════════════════════════════════════════ */
  window.QLP.notfound = function () {
    var page = $("#page");
    page.innerHTML = '<div class="notfound">' +
      '<img class="notfound-img" src="/static/images/404.jpg" alt="404 — page not found" width="1536" height="1024" loading="eager" decoding="async">' +
      "<h1>404</h1>" +
      "<div class='small muted' style='max-width:360px'>This page may have been moved, resolved, or never existed.</div>" +
      '<div style="display:flex;gap:8px;margin-top:10px"><a class="btn" href="#/overview">' + QL.icon("dashboard") + " Overview</a>" +
      '<a class="btn btn-ghost" href="#/search">' + QL.icon("search") + " Search</a></div></div>";
  };
})();
