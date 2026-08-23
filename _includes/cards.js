<script>
  (function () {
    var deck = document.querySelector('.card-deck');
    if (!deck) return;
    var cards = Array.prototype.slice.call(deck.querySelectorAll('.card'));
    var dotsWrap = document.querySelector('.card-dots');
    var prevBtn = document.querySelector('.card-arrow.prev');
    var nextBtn = document.querySelector('.card-arrow.next');
    var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    var dots = cards.map(function (_, i) {
      var b = document.createElement('button');
      b.className = 'card-dot';
      b.setAttribute('aria-label', 'Go to card ' + (i + 1));
      b.addEventListener('click', function () { goTo(i); });
      dotsWrap.appendChild(b);
      return b;
    });

    function activeIndex() {
      var center = deck.scrollLeft + deck.clientWidth / 2;
      var best = 0, bestDist = Infinity;
      cards.forEach(function (c, i) {
        var cCenter = c.offsetLeft + c.offsetWidth / 2;
        var dist = Math.abs(cCenter - center);
        if (dist < bestDist) { bestDist = dist; best = i; }
      });
      return best;
    }

    function render() {
      var idx = activeIndex();
      cards.forEach(function (c, i) { c.classList.toggle('is-active', i === idx); });
      dots.forEach(function (d, i) { d.classList.toggle('is-active', i === idx); });
      if (prevBtn) prevBtn.disabled = idx === 0;
      if (nextBtn) nextBtn.disabled = idx === cards.length - 1;
    }

    function goTo(i) {
      i = Math.max(0, Math.min(cards.length - 1, i));
      cards[i].scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', inline: 'center', block: 'nearest' });
    }

    var raf;
    deck.addEventListener('scroll', function () {
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(render);
    }, { passive: true });

    if (prevBtn) prevBtn.addEventListener('click', function () { goTo(activeIndex() - 1); });
    if (nextBtn) nextBtn.addEventListener('click', function () { goTo(activeIndex() + 1); });

    deck.setAttribute('tabindex', '0');
    deck.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowRight') { goTo(activeIndex() + 1); e.preventDefault(); }
      if (e.key === 'ArrowLeft') { goTo(activeIndex() - 1); e.preventDefault(); }
    });

    render();

    // --- physics: each card springs in from a random direction on load ---
    if (!reduceMotion) {
      cards.forEach(function (card, i) {
        var angle = Math.random() * Math.PI * 2;
        var distance = 260 + Math.random() * 220;
        var fromX = Math.cos(angle) * distance;
        var fromY = Math.sin(angle) * distance * 0.6; // flatten vertical throw a bit
        var fromRot = (Math.random() * 36) - 18;
        var fromScale = 0.55 + Math.random() * 0.15;

        card.style.transition = 'none';
        card.style.opacity = '0';
        card.style.transform = 'translate(' + fromX + 'px,' + fromY + 'px) rotate(' + fromRot + 'deg) scale(' + fromScale + ')';

        var delay = 90 * i + Math.random() * 60;
        setTimeout(function () {
          springTo(card, {
            x: fromX, y: fromY, rot: fromRot, scale: fromScale, opacity: 0
          }, {
            x: 0, y: 0, rot: 0, scale: 1, opacity: 1
          }, function () {
            // hand control back to CSS (.is-active class) for subsequent swipe transitions
            card.style.transition = '';
            card.style.transform = '';
            card.style.opacity = '';
            render();
          });
        }, delay);
      });
    }

    // damped mass-spring-damper simulation over translate/rotate/scale/opacity
    function springTo(el, from, to, onDone) {
      var pos = { x: from.x, y: from.y, rot: from.rot, scale: from.scale, opacity: from.opacity };
      var vel = { x: 0, y: 0, rot: 0, scale: 0, opacity: 0 };
      var stiffness = 140, damping = 16, mass = 1, dt = 1 / 60;
      var keys = ['x', 'y', 'rot', 'scale', 'opacity'];

      function step() {
        var settled = true;
        keys.forEach(function (k) {
          var delta = to[k] - pos[k];
          var accel = (stiffness * delta - damping * vel[k]) / mass;
          vel[k] += accel * dt;
          pos[k] += vel[k] * dt;
          if (Math.abs(delta) > 0.01 || Math.abs(vel[k]) > 0.01) settled = false;
        });

        el.style.transform = 'translate(' + pos.x.toFixed(2) + 'px,' + pos.y.toFixed(2) + 'px) rotate(' + pos.rot.toFixed(2) + 'deg) scale(' + pos.scale.toFixed(3) + ')';
        el.style.opacity = Math.max(0, Math.min(1, pos.opacity)).toFixed(3);

        if (settled) { if (onDone) onDone(); }
        else requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    }
  })();
</script>
