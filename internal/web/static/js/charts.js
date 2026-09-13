/* ─────────────────────────────────────────────────────────────
   Quetzalog charts — hand-rolled canvas renderers tuned for the
   observability look: quiet grids, accent lines, severity bars.
   ───────────────────────────────────────────────────────────── */
(function () {
  "use strict";

  var FONT = "11px Inter, ui-sans-serif, system-ui, sans-serif";
  var FONT_SM = "10px Inter, ui-sans-serif, system-ui, sans-serif";

  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }

  function prep(canvas) {
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    if (rect.width === 0) rect = { width: 600, height: 220 };
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    return { ctx: ctx, w: rect.width, h: rect.height };
  }

  function empty(ctx, w, h) {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = cssVar("--ql-text-faint", "#64748B");
    ctx.font = FONT;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("No data in this window", w / 2, h / 2);
  }

  function timeLabel(t, spanSec) {
    var d = new Date(t * 1000);
    var hh = d.getHours() < 10 ? "0" + d.getHours() : "" + d.getHours();
    var mm = d.getMinutes() < 10 ? "0" + d.getMinutes() : "" + d.getMinutes();
    if (spanSec > 86400 * 2) return (d.getMonth() + 1) + "/" + d.getDate() + " " + hh + ":" + mm;
    return hh + ":" + mm;
  }

  /* Smooth line + gradient area over [{t, v}] */
  function line(canvas, points, opts) {
    opts = opts || {};
    var p = prep(canvas), ctx = p.ctx;
    var w = p.w, h = p.h;
    if (!points.length) return empty(ctx, w, h);

    var padT = 14, padR = 12, padB = 26, padL = 42;
    var cw = w - padL - padR, ch = h - padT - padB;
    var maxV = opts.max || Math.max.apply(null, points.map(function (d) { return d.v; }));
    maxV = maxV * 1.15 || 1;

    ctx.clearRect(0, 0, w, h);
    ctx.font = FONT_SM;

    /* grid */
    ctx.strokeStyle = cssVar("--ql-border-soft", "#24304a");
    ctx.lineWidth = 1;
    ctx.fillStyle = cssVar("--ql-text-faint", "#64748B");
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (var g = 0; g <= 4; g++) {
      var y = padT + (g / 4) * ch;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
      ctx.fillText(QL.fmtNum(Math.round(maxV - (g / 4) * maxV)), padL - 8, y);
    }

    var color = opts.color || cssVar("--ql-secondary", "#06B6D4");
    var t0 = points[0].t, t1 = points[points.length - 1].t;
    var span = Math.max(1, t1 - t0);
    var pts = points.map(function (d, i) {
      return {
        x: padL + (points.length === 1 ? cw / 2 : ((d.t - t0) / span) * cw),
        y: padT + ((maxV - d.v) / maxV) * ch,
      };
    });

    /* area */
    ctx.beginPath();
    ctx.moveTo(pts[0].x, padT + ch);
    pts.forEach(function (pt) { ctx.lineTo(pt.x, pt.y); });
    ctx.lineTo(pts[pts.length - 1].x, padT + ch);
    ctx.closePath();
    var grad = ctx.createLinearGradient(0, padT, 0, padT + ch);
    grad.addColorStop(0, color + "3d");
    grad.addColorStop(1, color + "05");
    ctx.fillStyle = grad;
    ctx.fill();

    /* line */
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.moveTo(pts[0].x, pts[0].y);
    for (var i = 0; i < pts.length - 1; i++) {
      var cx = (pts[i].x + pts[i + 1].x) / 2;
      ctx.bezierCurveTo(cx, pts[i].y, cx, pts[i + 1].y, pts[i + 1].x, pts[i + 1].y);
    }
    ctx.stroke();

    /* x labels */
    ctx.fillStyle = cssVar("--ql-text-faint", "#64748B");
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    var step = Math.ceil(points.length / 7);
    for (var k = 0; k < points.length; k += step) {
      ctx.fillText(timeLabel(points[k].t, span), pts[k].x, padT + ch + 8);
    }
  }

  /* Horizontal bars [{label, value, color}] */
  function hbars(canvas, items, opts) {
    opts = opts || {};
    var p = prep(canvas), ctx = p.ctx;
    var w = p.w, h = p.h;
    if (!items.length) return empty(ctx, w, h);

    var labelW = Math.min(120, Math.max(72, ctx.measureText(items[0].label || "").width + 90));
    ctx.font = FONT;
    labelW = Math.min(120, Math.max(84, ctx.measureText(items[0].label || "").width + 18));
    var padT = 6, padB = 6, padR = 44;
    var rowH = Math.min(30, (h - padT - padB) / items.length - 5);
    var barH = Math.min(13, rowH - 6);
    var maxV = opts.max || Math.max.apply(null, items.map(function (d) { return d.value; })) || 1;
    var barW = w - labelW - padR;

    ctx.clearRect(0, 0, w, h);
    items.forEach(function (it, i) {
      var y = padT + i * (rowH + 5) + 3;
      /* label */
      ctx.font = FONT;
      ctx.fillStyle = cssVar("--ql-text-2", "#CBD5E1");
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      var label = it.label;
      if (ctx.measureText(label).width > labelW - 12) {
        while (ctx.measureText(label + "…").width > labelW - 12 && label.length > 4) label = label.slice(0, -2);
        label += "…";
      }
      ctx.fillText(label, labelW - 10, y + barH / 2);

      /* track + bar */
      ctx.beginPath();
      ctx.roundRect(labelW, y, barW, barH, 4);
      ctx.fillStyle = cssVar("--ql-surface-3", "#374151");
      ctx.globalAlpha = 0.35;
      ctx.fill();
      ctx.globalAlpha = 1;
      var bw = Math.max(3, (it.value / maxV) * barW);
      ctx.beginPath();
      ctx.roundRect(labelW, y, bw, barH, 4);
      ctx.fillStyle = it.color || cssVar("--ql-secondary", "#06B6D4");
      ctx.fill();

      ctx.font = FONT;
      ctx.fillStyle = cssVar("--ql-text-2", "#CBD5E1");
      ctx.textAlign = "left";
      ctx.fillText(QL.fmtNum(it.value), labelW + barW + 8, y + barH / 2);
    });
  }

  /* Security activity: event volume area + stacked finding bars by severity. */
  function activity(canvas, eventPoints, findingPoints, opts) {
    opts = opts || {};
    var p = prep(canvas), ctx = p.ctx;
    var w = p.w, h = p.h;

    var buckets = eventPoints.map(function (e) { return e.bucket; });
    if (!buckets.length && findingPoints.length) {
      buckets = findingPoints.map(function (f) { return f.bucket; });
    }
    if (!buckets.length) return empty(ctx, w, h);

    var t0 = buckets[0], t1 = buckets[buckets.length - 1];
    var span = Math.max(1, t1 - t0);

    /* merge finding points into buckets */
    var fmap = {};
    findingPoints.forEach(function (f) { fmap[f.bucket] = f.count; });

    var evMax = 0, fMax = 0;
    eventPoints.forEach(function (e) { evMax = Math.max(evMax, e.total); });
    buckets.forEach(function (b) { fMax = Math.max(fMax, fmap[b] || 0); });
    if (!evMax && !fMax) return empty(ctx, w, h);

    var padT = 16, padR = 12, padB = 26, padL = 44;
    var cw = w - padL - padR, ch = h - padT - padB;
    var evMaxS = evMax * 1.15 || 1;
    var fMaxS = Math.max(fMax * 1.4, 1);

    ctx.clearRect(0, 0, w, h);
    ctx.font = FONT_SM;
    ctx.strokeStyle = cssVar("--ql-border-soft", "#24304a");
    ctx.fillStyle = cssVar("--ql-text-faint", "#64748B");
    for (var g = 0; g <= 4; g++) {
      var y = padT + (g / 4) * ch;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
      ctx.textAlign = "right"; ctx.textBaseline = "middle";
      ctx.fillText(QL.fmtNum(Math.round(evMaxS - (g / 4) * evMaxS)), padL - 8, y);
    }

    var x = function (b) { return padL + ((b - t0) / span) * cw; };
    var evPts = eventPoints.map(function (e) { return { x: x(e.bucket), y: padT + (1 - e.total / evMaxS) * ch }; });

    /* event area */
    if (evPts.length) {
      ctx.beginPath();
      ctx.moveTo(evPts[0].x, padT + ch);
      evPts.forEach(function (pt) { ctx.lineTo(pt.x, pt.y); });
      ctx.lineTo(evPts[evPts.length - 1].x, padT + ch);
      ctx.closePath();
      var grad = ctx.createLinearGradient(0, padT, 0, padT + ch);
      grad.addColorStop(0, cssVar("--ql-secondary", "#06B6D4") + "33");
      grad.addColorStop(1, cssVar("--ql-secondary", "#06B6D4") + "04");
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.beginPath();
      ctx.strokeStyle = cssVar("--ql-secondary", "#06B6D4");
      ctx.lineWidth = 1.5;
      ctx.globalAlpha = 0.75;
      ctx.moveTo(evPts[0].x, evPts[0].y);
      for (var i = 0; i < evPts.length - 1; i++) {
        var cx = (evPts[i].x + evPts[i + 1].x) / 2;
        ctx.bezierCurveTo(cx, evPts[i].y, cx, evPts[i + 1].y, evPts[i + 1].x, evPts[i + 1].y);
      }
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    /* finding bars, stacked by severity */
    var sevKeys = [
      { key: "critical", color: cssVar("--ql-sev-critical", "#EF4444") },
      { key: "high", color: cssVar("--ql-sev-high", "#F97316") },
      { key: "medium", color: cssVar("--ql-sev-medium", "#F59E0B") },
      { key: "low", color: cssVar("--ql-sev-low", "#3B82F6") },
    ];
    var n = buckets.length;
    var slot = cw / Math.max(1, n);
    var bw = Math.min(18, Math.max(2.5, slot * 0.55));

    buckets.forEach(function (b, i) {
      var fCount = fmap[b];
      if (!fCount) return;
      var bx = x(b) - bw / 2;
      var yCursor = padT + ch;
      var totalPx = Math.min(fCount / fMaxS, 1) * ch;
      var parts = eventPoints[i] ? [
        { v: eventPoints[i].critical, color: sevKeys[0].color },
        { v: eventPoints[i].high, color: sevKeys[1].color },
        { v: eventPoints[i].medium, color: sevKeys[2].color },
        { v: eventPoints[i].low, color: sevKeys[3].color },
      ] : null;
      var base = evMax ? eventPoints[i].total : 0;
      var stack = parts && base
        ? parts.map(function (s) { return { v: s.v, color: s.color, f: base ? s.v / base : 0 }; })
        : [{ v: fCount, color: cssVar("--ql-feather-red", "#EF4444"), f: 1 }];
      stack.forEach(function (s) {
        var seg = (s.f * totalPx);
        if (seg < 0.8) return;
        ctx.fillStyle = s.color;
        ctx.beginPath();
        ctx.roundRect(bx, yCursor - seg, bw, seg, 1.5);
        ctx.fill();
        yCursor -= seg;
      });
    });

    /* x labels */
    ctx.fillStyle = cssVar("--ql-text-faint", "#64748B");
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    var step = Math.ceil(n / 7);
    for (var k = 0; k < n; k += step) {
      ctx.fillText(timeLabel(buckets[k], span), x(buckets[k]), padT + ch + 8);
    }
  }

  function severityBars(canvas, entries) {
    /* entries: [{label, value, color}] */
    var p = prep(canvas), ctx = p.ctx;
    if (!entries.length) return empty(ctx, p.w, p.h);
    var maxV = Math.max.apply(null, entries.map(function (d) { return d.value; })) || 1;
    var padL = 78, padR = 46, padT = 4, padB = 4;
    var rowH = Math.min(26, (p.h - padT - padB) / entries.length - 4);
    var barH = Math.min(12, rowH - 4);
    var barW = p.w - padL - padR;

    ctx.clearRect(0, 0, p.w, p.h);
    ctx.font = FONT;
    entries.forEach(function (it, i) {
      var y = padT + i * (rowH + 4);
      ctx.fillStyle = cssVar("--ql-text-2", "#CBD5E1");
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText(it.label, padL - 10, y + barH / 2);
      ctx.beginPath();
      ctx.roundRect(padL, y, barW, barH, 4);
      ctx.fillStyle = cssVar("--ql-surface-3", "#374151");
      ctx.globalAlpha = 0.3;
      ctx.fill();
      ctx.globalAlpha = 1;
      var bw = Math.max(2, (it.value / maxV) * barW);
      ctx.beginPath();
      ctx.roundRect(padL, y, bw, barH, 4);
      ctx.fillStyle = it.color;
      ctx.fill();
      ctx.fillStyle = cssVar("--ql-text-2", "#CBD5E1");
      ctx.textAlign = "left";
      ctx.fillText(QL.fmtNum(it.value), padL + barW + 8, y + barH / 2);
    });
  }

  window.QL = window.QL || {};
  window.QL.charts = { line: line, hbars: hbars, activity: activity, severityBars: severityBars };
})();
