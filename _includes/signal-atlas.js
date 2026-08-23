<script>
  // Signal Atlas: decorative rotating-globe visualization for the Research
  // page. Illustrative only - simulated events, not real threat telemetry.
  (function () {
    var canvas = document.getElementById('atlasCanvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);

    function getColor(v) { return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }
    function hexToRgb(c) {
      if (c.indexOf('rgb') === 0) { var m = c.match(/[\d.]+/g); return { r: +m[0], g: +m[1], b: +m[2] }; }
      var h = c.replace('#', ''); if (h.length === 3) h = h.split('').map(function (x) { return x + x; }).join('');
      var n = parseInt(h, 16); return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
    }

    function resize() {
      // deferred to the next paint frame so we read dimensions after layout
      // (e.g. the sidebar/main grid collapsing at the $desktop breakpoint)
      // has actually settled, not mid-reflow
      requestAnimationFrame(function () {
        var rect = canvas.getBoundingClientRect();
        // a transient 0-size read (common during a resize/breakpoint
        // transition) would collapse the whole globe to a single point -
        // skip it and just wait for the next real resize event instead
        if (rect.width < 10 || rect.height < 10) return;
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
      });
    }
    resize();
    window.addEventListener('resize', resize);

    // rotating globe: continents as rough lat/lon regions, sampled into dots
    // on the sphere, projected orthographically each frame as it spins.
    // cx,cy reuse an equirectangular-style placement (0..1) purely as an
    // authoring convenience, converted once into lat/lon (radians)
    var landRegions = [
      { cx: 0.16, cy: 0.30, rx: 0.09, ry: 0.14, rot: -0.2, name: 'North America' },
      { cx: 0.12, cy: 0.20, rx: 0.05, ry: 0.06, rot: 0, name: 'North America' },
      { cx: 0.22, cy: 0.62, rx: 0.05, ry: 0.16, rot: 0.15, name: 'South America' },
      { cx: 0.47, cy: 0.24, rx: 0.045, ry: 0.06, rot: 0, name: 'Europe' },
      { cx: 0.49, cy: 0.48, rx: 0.07, ry: 0.16, rot: 0, name: 'Africa' },
      { cx: 0.63, cy: 0.26, rx: 0.14, ry: 0.10, rot: 0.05, name: 'Asia' },
      { cx: 0.72, cy: 0.38, rx: 0.08, ry: 0.09, rot: -0.1, name: 'Southeast Asia' },
      { cx: 0.80, cy: 0.68, rx: 0.05, ry: 0.035, rot: 0, name: 'Australia' }
    ];

    function toVec3(lat, lon) {
      return [Math.cos(lat) * Math.sin(lon), Math.sin(lat), Math.cos(lat) * Math.cos(lon)];
    }
    function regionCenter(r) { return [(0.5 - r.cy) * Math.PI, (r.cx - 0.5) * Math.PI * 2]; }

    var landDots = []; // array of unit vec3
    landRegions.forEach(function (r) {
      var center = regionCenter(r);
      var dlat = r.ry * Math.PI, dlon = r.rx * Math.PI * 2;
      var count = Math.floor((r.rx * r.ry) * 3200);
      for (var i = 0; i < count; i++) {
        var a = Math.random() * Math.PI * 2;
        var d = Math.sqrt(Math.random());
        var lx = Math.cos(a) * d * dlon;
        var ly = Math.sin(a) * d * dlat;
        var lon = center[1] + lx * Math.cos(r.rot) - ly * Math.sin(r.rot);
        var lat = center[0] + lx * Math.sin(r.rot) + ly * Math.cos(r.rot);
        lat = Math.max(-Math.PI / 2 + 0.05, Math.min(Math.PI / 2 - 0.05, lat));
        landDots.push(toVec3(lat, lon));
      }
    });

    // node hotspots: placed with a golden-angle spiral inside each landmass
    // (the same phyllotaxis pattern sunflower seeds/pinecones use) instead of
    // an even grid - organic, non-repeating spacing, still visually clustered
    // per continent
    var GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5)); // ~137.5 deg
    var nodes = []; // { vec: [x,y,z], region: string }
    landRegions.forEach(function (r, ri) {
      var center = regionCenter(r);
      var dlat = r.ry * Math.PI, dlon = r.rx * Math.PI * 2;
      var perRegion = 2 + (ri % 2); // 2-3 nodes per landmass
      for (var k = 0; k < perRegion; k++) {
        var idx = k + 1;
        var angle = idx * GOLDEN_ANGLE;
        var radius = Math.sqrt(idx / perRegion) * 0.62; // stay inside the blob
        var lx = Math.cos(angle) * radius * dlon;
        var ly = Math.sin(angle) * radius * dlat;
        var lon = center[1] + lx * Math.cos(r.rot) - ly * Math.sin(r.rot);
        var lat = center[0] + lx * Math.sin(r.rot) + ly * Math.cos(r.rot);
        nodes.push({ vec: toVec3(lat, lon), region: r.name });
      }
    });

    // rotate around the vertical (Y) axis - the globe's actual spin
    function rotY(v, a) {
      var c = Math.cos(a), s = Math.sin(a);
      return [v[0] * c + v[2] * s, v[1], -v[0] * s + v[2] * c];
    }
    function slerp(a, b, t) {
      var dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
      var theta = Math.acos(dot) * t;
      var rx = b[0] - a[0] * dot, ry = b[1] - a[1] * dot, rz = b[2] - a[2] * dot;
      var rl = Math.sqrt(rx * rx + ry * ry + rz * rz) || 1;
      rx /= rl; ry /= rl; rz /= rl;
      var cosT = Math.cos(theta), sinT = Math.sin(theta);
      return [a[0] * cosT + rx * sinT, a[1] * cosT + ry * sinT, a[2] * cosT + rz * sinT];
    }

    var arcs = [];
    var eventCount = 0;
    var feedEl = document.getElementById('atlasFeed');
    var evCountEl = document.getElementById('atlasEvents');
    var arcCountEl = document.getElementById('atlasArcs');
    var labels = [
      'Kerberoasting attempt', 'encoded PowerShell', 'WMI lateral movement',
      'C2 beacon check-in', 'reverse shell spawn', 'credential stuffing',
      'RDP brute force', 'DNS exfiltration', 'npm postinstall payload',
      'supply-chain compromise', 'zero-day exploitation', 'privilege escalation',
      'agentic malware activity', 'OAuth token abuse', 'cloud IAM anomaly',
      'ransomware precursor', 'AnyDesk/PsExec sequence', 'auth anomaly', 'scan burst'
    ];

    // only spawn between nodes that are currently on the visible hemisphere -
    // otherwise the arc's path gets clipped by the globe's edge and the ray
    // appears to start from empty space instead of a real point
    function isVisible(vec) { return rotY(vec, rotation)[2] > 0.08; }

    function spawnArc() {
      var visible = nodes.filter(function (n) { return isVisible(n.vec); });
      if (visible.length < 2) return;
      var na = visible[Math.floor(Math.random() * visible.length)];
      var nb, attempts = 0;
      // avoid picking two nodes from the same landmass - "North America ->
      // North America" reads as a bug, not a global activity feed
      do {
        nb = visible[Math.floor(Math.random() * visible.length)];
        attempts++;
      } while ((nb === na || nb.region === na.region) && attempts < 8);
      if (nb === na || nb.region === na.region) return;
      arcs.push({ a: na.vec, b: nb.vec, t: 0, speed: 0.006 + Math.random() * 0.006, life: 1 });
      eventCount++;
      if (evCountEl) evCountEl.textContent = eventCount;
      var label = labels[Math.floor(Math.random() * labels.length)];
      if (feedEl) feedEl.innerHTML = '<span>[' + new Date().toISOString().substr(11, 8) + ']</span> ' + label + ' <b>' + na.region + ' → ' + nb.region + '</b>';
    }

    // spawn cadence walks a golden-ratio progression rather than a flat
    // interval - each gap is the previous one scaled by 1/phi or phi
    // (chosen per-step), so arcs arrive in bursts and lulls, never metronomic
    var PHI = 1.6180339887498949;
    var spawnTimer = 0;
    var nextSpawnAt = 18;
    function nextGap() {
      var base = 14 + Math.random() * 10;
      return Math.random() < 0.5 ? base / PHI : base * (PHI - 1);
    }

    var rotation = 0;
    var ROT_SPEED = 0.0013; // slow, majestic - one full spin in ~80s at 60fps

    function draw() {
      var w = canvas.width, h = canvas.height;
      // defense in depth: never let a degenerate canvas size (mid-resize,
      // mid-reflow) propagate into the projection math - just skip the
      // frame and try again next tick instead of drawing garbage or
      // throwing and killing the animation loop
      if (w < 10 || h < 10) {
        rotation += ROT_SPEED;
        if (!reduceMotion) requestAnimationFrame(draw);
        return;
      }
      ctx.clearRect(0, 0, w, h);

      var cx = w / 2, cy = h / 2;
      var R = Math.min(w, h) * 0.42;

      var dotColor = getColor('--dot');
      var borderColor = getColor('--border-strong');
      var gridColor = getColor('--grid-line');
      var accentRgb = hexToRgb(getColor('--accent-text'));
      var rayRgb = { r: 255, g: 61, b: 48 }; // beaming rays: hot red
      var raySolid = 'rgb(' + rayRgb.r + ',' + rayRgb.g + ',' + rayRgb.b + ')';

      function proj(v) {
        var rv = rotY(v, rotation);
        return { x: cx + R * rv[0], y: cy - R * rv[1], z: rv[2] };
      }
      function visAlpha(z) { return Math.max(0, Math.min(1, (z + 0.12) / 0.45)); }

      // small 4-point star/sparkle - alternating outer/inner radius, cheap
      // to draw at scale and reads distinctly from a plain dot even tiny
      function drawStar(x, y, r, alpha, color) {
        var outer = r, inner = r * 0.4;
        ctx.beginPath();
        for (var i = 0; i < 8; i++) {
          var rad = (i % 2 === 0) ? outer : inner;
          var ang = (Math.PI / 4) * i - Math.PI / 2;
          var px = x + Math.cos(ang) * rad, py = y + Math.sin(ang) * rad;
          if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fillStyle = color;
        ctx.globalAlpha = alpha;
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // globe silhouette (orthographic projection of a sphere's edge is
      // always a circle, so this alone doesn't need to rotate)
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.strokeStyle = borderColor;
      ctx.lineWidth = 1.2 * dpr;
      ctx.stroke();

      // latitude graticule - flattened ellipses, a common cheat to suggest
      // curvature in an orthographic view (true ortho would render as flat
      // lines, which reads as broken rather than "globe")
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1 * dpr;
      [-0.75, -0.41, 0, 0.41, 0.75].forEach(function (lat) {
        var ey = cy - R * Math.sin(lat);
        var erx = R * Math.cos(lat);
        ctx.beginPath();
        ctx.ellipse(cx, ey, erx, erx * 0.22, 0, 0, Math.PI * 2);
        ctx.stroke();
      });

      // landmass dots, drawn as tiny stars
      landDots.forEach(function (v) {
        var p = proj(v);
        var a = visAlpha(p.z);
        if (a <= 0.02) return;
        drawStar(p.x, p.y, 1.7 * dpr, a, dotColor);
      });

      // node hotspots
      nodes.forEach(function (n) {
        n.proj = proj(n.vec);
        var a = visAlpha(n.proj.z);
        if (a <= 0.02) return;
        ctx.beginPath();
        ctx.arc(n.proj.x, n.proj.y, 1.8 * dpr, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(' + accentRgb.r + ',' + accentRgb.g + ',' + accentRgb.b + ',' + (0.5 * a) + ')';
        ctx.fill();
      });

      // arcs: great-circle path (slerp) between two node vectors, with a
      // radial "lift" bulge at the midpoint so it reads as flying over the
      // globe's surface rather than burrowing through it
      arcs = arcs.filter(function (arc) { return arc.life > 0; });
      arcs.forEach(function (arc) {
        arc.t += arc.speed;
        if (arc.t > 1) { arc.t = 1; arc.life -= 0.03; }

        function pointAt(t) {
          var s = slerp(arc.a, arc.b, t);
          var bulge = 1 + 0.22 * Math.sin(t * Math.PI);
          return proj([s[0] * bulge, s[1] * bulge, s[2] * bulge]);
        }

        ctx.beginPath();
        var steps = 28;
        var started = false;
        for (var i = 0; i <= steps; i++) {
          var tt = (i / steps) * arc.t;
          var pt = pointAt(tt);
          var a = visAlpha(pt.z) * arc.life;
          if (a <= 0.03) { started = false; continue; }
          if (!started) { ctx.moveTo(pt.x, pt.y); started = true; }
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.strokeStyle = 'rgba(' + rayRgb.r + ',' + rayRgb.g + ',' + rayRgb.b + ',' + (0.6 * arc.life) + ')';
        ctx.lineWidth = 1 * dpr;
        ctx.stroke();

        if (arc.t < 1) {
          var head = pointAt(arc.t);
          var ha = visAlpha(head.z);
          if (ha > 0.05) {
            ctx.beginPath();
            ctx.shadowColor = raySolid;
            ctx.shadowBlur = 9;
            ctx.fillStyle = raySolid;
            ctx.globalAlpha = ha;
            ctx.arc(head.x, head.y, 2 * dpr, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1;
          }
        }
      });

      if (arcCountEl) arcCountEl.textContent = arcs.length;

      spawnTimer++;
      if (spawnTimer > nextSpawnAt) {
        if (arcs.length < 9) spawnArc();
        spawnTimer = 0;
        nextSpawnAt = nextGap();
      }

      rotation += ROT_SPEED;
      if (!reduceMotion) requestAnimationFrame(draw);
    }

    for (var i = 0; i < 3; i++) spawnArc();
    draw();
  })();
</script>
