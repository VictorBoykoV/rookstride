/* Progressive enhancement only. Documentation and stories are static HTML. */
(() => {
  'use strict';
  document.documentElement.classList.add('js');
  const toast = document.querySelector('.toast');
  let toastTimer;
  function announce(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 3500);
  }

  const menu = document.querySelector('.menu-toggle');
  const nav = document.querySelector('.site-nav');
  if (menu && nav) {
    function closeMenu() {
      menu.setAttribute('aria-expanded', 'false');
      nav.classList.remove('open');
    }
    menu.addEventListener('click', () => {
      const open = menu.getAttribute('aria-expanded') !== 'true';
      menu.setAttribute('aria-expanded', String(open));
      nav.classList.toggle('open', open);
    });
    nav.addEventListener('click', event => { if (event.target.closest('a')) closeMenu(); });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && menu.getAttribute('aria-expanded') === 'true') {
        closeMenu();
        menu.focus();
      }
    });
  }

  document.querySelectorAll('[data-copy]').forEach(control => {
    control.addEventListener('click', async () => {
      try {
        if (!navigator.clipboard) throw new Error('Clipboard not available');
        await navigator.clipboard.writeText(control.dataset.copy);
        announce('Copied.');
      } catch (_) {
        announce('Clipboard access is unavailable. Select and copy the visible text.');
      }
    });
  });

  const stage = document.querySelector('.book-stage');
  if (!stage) return;
  try {
    const pages = Array.from(document.querySelector('.book-page-source').querySelectorAll('.comic-page'));
    const chapter = document.querySelector('#chapter-select');
    if (!pages.length || pages.length !== chapter.options.length * 2 || pages.some(p => p.querySelectorAll('.comic-panel').length !== 3)) throw new Error('Incomplete journal');
    const right = stage.querySelector('.right-slot');
    const spread = stage.querySelector('.book-spread');
    const previous = document.querySelector('.book-prev');
    const next = document.querySelector('.book-next');
    const status = document.querySelector('.book-status');
    const motionControl = document.querySelector('.motion-toggle');
    const modes = Array.from(document.querySelectorAll('[data-reader-mode]'));
    const reduced = matchMedia('(prefers-reduced-motion: reduce)');
    const titles = Array.from(chapter.options).map(o => o.textContent.replace(/^\d+\s*—\s*/, ''));
    const total = pages.length * 3;
    let cursor = 0, mode = 'page', turning = false, pauseMotion = false;
    let animation = null, leaf = null, turnToken = 0;
    function stride() { return mode === 'panel' ? 1 : mode === 'page' ? 3 : 6; }
    function motionOff() { return pauseMotion || reduced.matches; }
    function readHash() {
      const match = /^#chapter-(\d+)(?:-(page|panel)-(\d+)|-(overview))?$/.exec(location.hash);
      if (!match) return;
      const c = Number(match[1]) - 1;
      if (c < 0 || c >= titles.length) return;
      const m = match[4] ? 'chapter' : match[2] || 'page';
      const unit = match[3] ? Number(match[3]) - 1 : 0;
      if (unit < 0 || unit >= (m === 'panel' ? 6 : m === 'page' ? 2 : 1)) return;
      mode = m; cursor = c * 6 + unit * (m === 'page' ? 3 : 1);
    }
    readHash();
    function remember() {
      const c = Math.floor(cursor / 6) + 1;
      const suffix = mode === 'chapter' ? '-overview' : `-${mode}-${mode === 'page' ? Math.floor(cursor % 6 / 3) + 1 : cursor % 6 + 1}`;
      history.replaceState(null, '', `#chapter-${c}${suffix}`);
    }
    function unit(index) {
      const c = Math.floor(index / 6);
      const clone = pages[mode === 'chapter' ? c * 2 : Math.floor(index / 3)].cloneNode(true);
      clone.removeAttribute('id');
      if (mode === 'panel') {
        clone.classList.add('single-panel');
        clone.querySelector('.panel-viewport').setAttribute('preserveAspectRatio', 'xMidYMid meet');
        Array.from(clone.querySelectorAll('.comic-panel')).forEach((p,i) => { if (i !== index % 3) p.remove(); });
        clone.setAttribute('aria-label', `${titles[c]}: panel ${index % 6 + 1}`);
        clone.querySelector('.page-number span:last-child').textContent = `PANEL ${index % 6 + 1} / 6`;
      } else if (mode === 'chapter') {
        clone.classList.add('chapter-overview');
        const content = clone.querySelector('.comic-panels');
        const img = document.createElement('img');
        img.src = clone.dataset.image; img.width = 1448; img.height = 1086;
        img.alt = `All six illustrations of ${titles[c]}. Read the left column down, then the right. Choose Panel or Page for captions, or read the complete text edition.`;
        const theme = document.createElement('p'); theme.className = 'chapter-theme'; theme.textContent = clone.dataset.theme;
        content.replaceChildren(img, theme);
        clone.setAttribute('aria-label', `Whole chapter ${c + 1}: ${titles[c]}`);
        clone.querySelector('.page-number span:last-child').textContent = `CHAPTER ${c + 1} / ${titles.length}`;
      }
      return clone;
    }
    function updateControls() {
      previous.disabled = turning || cursor === 0;
      next.disabled = turning || cursor + stride() >= total;
      chapter.disabled = turning; chapter.value = String(Math.floor(cursor / 6));
      modes.forEach(b => { b.disabled = turning; b.setAttribute('aria-pressed', String(b.dataset.readerMode === mode)); });
      const label = mode === 'chapter' ? 'Chapter' : mode === 'panel' ? 'Panel' : 'Page';
      status.textContent = `${titles[Math.floor(cursor / 6)]} · ${label} ${Math.floor(cursor / stride()) + 1} of ${total / stride()}`;
      previous.setAttribute('aria-label', `Previous ${label.toLowerCase()}`);
      next.setAttribute('aria-label', `Next ${label.toLowerCase()}`);
      motionControl.setAttribute('aria-pressed', String(motionOff()));
      motionControl.querySelector('span').textContent = reduced.matches ? 'Reduced motion' : pauseMotion ? 'Page turns off' : 'Page turns on';
      document.querySelector('.book-hint').textContent = mode === 'chapter' ? 'Read the left column down, then the right · Arrow keys, drag or swipe' : mode === 'panel' ? 'One scene at a time · Arrow keys, artwork drag or swipe' : 'Read top to bottom · Arrow keys, artwork drag or swipe';
      stage.setAttribute('aria-busy', String(turning));
      stage.setAttribute('aria-label', `Comic ${label.toLowerCase()} view. Use arrow keys, drag artwork or swipe to turn.`);
    }
    function render() {
      cursor = Math.floor(cursor / stride()) * stride();
      stage.dataset.mode = mode;
      right.replaceChildren(unit(cursor));
      updateControls();
    }
    function cancelTurn() {
      ++turnToken;
      if (animation) animation.cancel();
      animation = null;
      if (leaf) leaf.remove();
      leaf = null; turning = false;
      stage.classList.remove('turning'); spread.removeAttribute('aria-hidden');
    }
    async function turn(direction) {
      if (turning) return;
      const target = cursor + direction * stride();
      if (target < 0 || target >= total) return;
      if (motionOff() || !Element.prototype.animate) { cursor = target; render(); remember(); return; }
      turning = true;
      const token = ++turnToken;
      stage.classList.add('turning'); updateControls(); spread.setAttribute('aria-hidden', 'true');
      leaf = document.createElement('div');
      leaf.className = `turn-leaf ${direction > 0 ? 'forward' : 'backward'}`; leaf.setAttribute('aria-hidden', 'true');
      const front = document.createElement('div'); front.className = 'turn-face turn-front'; front.append(unit(cursor));
      const back = document.createElement('div'); back.className = 'turn-face turn-back'; back.append(unit(target));
      right.replaceChildren(unit(target)); leaf.append(front, back); stage.append(leaf);
      animation = leaf.animate([{transform:'rotateY(0deg)'},{transform:`rotateY(${direction > 0 ? -180 : 180}deg)`}], {duration:900,easing:'cubic-bezier(.4,.05,.2,1)',fill:'forwards'});
      try { await animation.finished; } catch (_) { return; }
      if (token !== turnToken) return;
      cursor = target; cancelTurn(); render(); remember();
    }
    previous.addEventListener('click', () => turn(-1));
    next.addEventListener('click', () => turn(1));
    stage.addEventListener('keydown', event => {
      if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') { event.preventDefault(); turn(event.key === 'ArrowRight' ? 1 : -1); }
      else if (event.key === 'Home' || event.key === 'End') {
        event.preventDefault(); if (turning) return;
        cursor = event.key === 'Home' ? 0 : total - stride(); render(); remember();
      }
    });
    function goChapter(value) { cancelTurn(); cursor = Number(value) * 6; render(); remember(); }
    chapter.addEventListener('change', () => goChapter(chapter.value));
    modes.forEach(control => control.addEventListener('click', () => {
      cancelTurn(); mode = control.dataset.readerMode; render(); remember();
    }));
    document.querySelectorAll('[data-chapter]').forEach(link => link.addEventListener('click', event => {
      event.preventDefault(); goChapter(link.dataset.chapter);
      document.querySelector('#reader').scrollIntoView({behavior:reduced.matches?'auto':'smooth',block:'start'});
      stage.focus({preventScroll:true});
    }));
    motionControl.addEventListener('click', () => {
      pauseMotion = !pauseMotion;
      if (turning) { cancelTurn(); render(); }
      updateControls();
      if (reduced.matches) announce('Your system requests reduced motion. Page changes stay instant.');
    });
    reduced.addEventListener('change', () => { cancelTurn(); render(); });
    window.addEventListener('hashchange', () => { cancelTurn(); readHash(); render(); });
    let touchStart = null;
    stage.addEventListener('pointerdown', event => {
      if (event.pointerType === 'mouse') {
        if (event.button !== 0 || !event.target.closest('.panel-art, .chapter-overview img')) return;
        event.preventDefault(); stage.setPointerCapture(event.pointerId);
      }
      touchStart = {x:event.clientX,y:event.clientY};
    });
    stage.addEventListener('pointercancel', () => { touchStart = null; });
    stage.addEventListener('pointerup', event => {
      if (!touchStart) return;
      const dx=event.clientX-touchStart.x, dy=event.clientY-touchStart.y; touchStart=null;
      if (Math.abs(dx)>50 && Math.abs(dx)>Math.abs(dy)*1.5) turn(dx<0?1:-1);
    });
    render();
  } catch (error) {
    document.documentElement.classList.add('book-fallback');
    console.error('Journal enhancement unavailable:', error.message);
  }
})();
