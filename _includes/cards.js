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
  })();
</script>
