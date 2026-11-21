/* Offline first: text and art are bundled, with no account or native interfaces. */
(function () {
  'use strict';
  var root = document.getElementById('reader');
  var catalog;
  var current;
  var last;
  var pendingTurn = 0;
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function button(text, cls, action) {
    var n = el('button', cls, text);
    n.type = 'button';
    n.addEventListener('click', action);
    return n;
  }
  function append(parent) {
    for (var i = 1; i < arguments.length; i++) parent.appendChild(arguments[i]);
    return parent;
  }
  function chapter(id) {
    return catalog.chapters.filter(function (c) { return c.id === id; })[0];
  }
  function parse() {
    var p = location.hash.slice(1).split('/');
    var c = chapter(p[1]);
    if ((p[0] === 'read' || p[0] === 'library') && c) {
      return {screen:p[0], chapter:c.id, page:Math.max(1, Math.min(c.pages.length, parseInt(p[2],10)||1)),
        panel:Math.max(1, Math.min(6, parseInt(p[3],10)||1)), mode:p[4] === 'page' ? 'page' : 'panel', end:p[5] === 'end'};
    }
    return {screen:'library'};
  }
  function url(s) {
    return '#' + s.screen + (s.chapter ? '/' + s.chapter + '/' + s.page + '/' + s.panel + '/' + s.mode + (s.end ? '/end' : '') : '');
  }
  function go(s, push) {
    if (push && url(s) !== location.hash) {
      location.hash = url(s);
    } else {
      history.replaceState(null, '', url(s));
      render();
    }
  }
  function copy(s, changes) {
    var next = {};
    Object.keys(s).forEach(function (key) { next[key] = s[key]; });
    Object.keys(changes).forEach(function (key) { next[key] = changes[key]; });
    return next;
  }
  function library() {
    var out = el('section', 'library');
    out.setAttribute('data-library', 'persia');
    var intro = el('header', 'intro');
    append(intro,append(el('div','library-title'),el('h1','',catalog.world.title),el('p','eyebrow',"Rook's stories")),
      el('p','muted',catalog.world.subtitle));
    out.appendChild(intro);
    if (last && last.chapter) {
      var c = chapter(last.chapter);
      var resume = button('Continue reading', 'resume', function () { go(copy(last,{screen:'read'}),true); });
      resume.setAttribute('data-resume','');
      resume.appendChild(el('small','',c.title + ' · Page ' + last.page + ' of ' + c.pages.length));
      out.appendChild(resume);
    }
    var list = el('div','chapter-list');
    catalog.chapters.forEach(function (c) {
      var card = el('article','chapter-card');
      var cover = el('div','chapter-cover');
      var coverImage = el('img','');
      coverImage.src = c.pages[0].image;
      coverImage.alt = '';
      cover.appendChild(coverImage);
      var text = el('div','chapter-copy');
      append(text, el('p','eyebrow','Chapter ' + c.number), el('h2','',c.title),
        el('p','chapter-meta',c.pages.length + ' pages · ' + (c.pages.length * 6) + ' panels'));
      var start = button('Start chapter', '', function () {
        go({screen:'read',chapter:c.id,page:1,panel:1,mode:'panel',end:false},true);
      });
      start.setAttribute('data-open-chapter', c.id);
      text.appendChild(start);
      card.appendChild(append(el('div','chapter-main'),cover,text));
      var preview = el('details','chapter-preview');
      append(preview,el('summary','','Story preview'),el('p','',c.summary));
      card.appendChild(preview);
      list.appendChild(card);
    });
    out.appendChild(list);
    var about = el('details','series-about');
    append(about,el('summary','','About this adventure'),el('h2','',catalog.world.seriesTitle),el('p','',catalog.world.description));
    out.appendChild(about);
    var meet = el('details','meet-cast');
    meet.appendChild(el('summary','', 'Meet Rook and his friends'));
    var cast = el('ul','cast-list');
    catalog.world.cast.forEach(function (person) {
      var item = el('li','');
      append(item,el('strong','',person.name + '. '),el('span','',person.description));
      cast.appendChild(item);
    });
    meet.appendChild(cast);
    out.appendChild(meet);
    out.appendChild(el('p','library-footer','Original stories for curious minds. Read offline, at your own pace.'));
    return out;
  }
  function panelText(panel, number, wholePage) {
    var text = el('section','story-copy');
    text.setAttribute('data-panel-copy',String(number));
    text.appendChild(el('h2','',wholePage ? 'Panel ' + number : 'The story'));
    if (panel.narration) text.appendChild(el('p','narration',panel.narration));
    panel.dialogue.forEach(function (line) {
      var dialogue = el('p','dialogue');
      append(dialogue,el('span','speaker',line.speaker + ': '),el('span','',line.text));
      text.appendChild(dialogue);
    });
    return text;
  }
  function advance(direction) {
    var c = chapter(current.chapter);
    var s = copy(current,{});
    if (s.end) { s.end = false; go(s,false); return; }
    if (s.mode === 'panel') {
      s.panel += direction;
      if (s.panel > 6) { s.panel = 1; s.page++; }
      if (s.panel < 1) { s.panel = 6; s.page--; }
    } else s.page += direction;
    if (s.page > c.pages.length) {
      s.page = c.pages.length; s.panel = 6; s.end = true;
    }
    if (s.page < 1) return;
    pendingTurn = direction;
    go(s,false);
  }
  function reading() {
    var c = chapter(current.chapter);
    var page = c.pages[current.page - 1];
    var out = el('section','reading');
    out.setAttribute('data-reader-mode',current.mode);
    out.setAttribute('data-chapter',c.id);
    var head = el('header','read-head');
    var top = el('div','read-topline');
    var context = el('div','read-location');
    append(context,el('p','eyebrow',catalog.world.title + ' · Chapter ' + c.number),el('h1','',c.title));
    var position = el('p','position','Page ' + current.page + '/' + c.pages.length + (current.mode === 'panel' ? ' · Panel ' + current.panel + '/6' : ' · 6 panels'));
    position.setAttribute('data-position','');
    position.setAttribute('aria-live','polite');
    var modes = el('div','modes');
    modes.setAttribute('aria-label','Reading view');
    ['panel','page'].forEach(function (mode) {
      var control = button(mode === 'panel' ? 'One panel' : 'Full page','',function () { go(copy(current,{mode:mode,end:false}),false); });
      control.setAttribute('aria-pressed',String(current.mode === mode));
      control.setAttribute('data-mode',mode);
      modes.appendChild(control);
    });
    context.appendChild(position);
    append(top,button('‹ Chapters','read-back',function () { go(copy(current,{screen:'library'}),true); }),context);
    append(head,top,modes);out.appendChild(head);
    if (current.end) {
      var end = el('section','chapter-finished');
      end.setAttribute('data-chapter-finished','');
      append(end,el('p','eyebrow','Chapter complete'),el('h2','',c.title),el('p','',c.cliffhanger));
      var note = el('details','field-note');
      append(note,el('summary','',"Rook's field note"),el('p','',c.lesson));
      end.appendChild(note);
      if (catalog.chapters.some(function (other) { return other.number > c.number; }))
        end.appendChild(el('p','next-chapter-note','The next chapter starts when you choose it.'));
      else end.appendChild(el('p','next-chapter-note','Rook will return. This adventure continues in a future chapter.'));
      end.appendChild(button('Back to chapters','',function () { go(copy(current,{screen:'library'}),true); }));
      out.appendChild(end);
    } else {
      var stage = el('div','story-stage' + (pendingTurn > 0 ? ' turn-forward' : pendingTurn < 0 ? ' turn-backward' : ''));
      var art = el('div','art-frame mode-' + current.mode + ' frame-' + current.panel);
      var image = el('img','');
      image.src = page.image;
      image.alt = current.mode === 'panel' ? page.panels[current.panel-1].alt : 'Six-panel comic page. Choose a panel for its description and story text.';
      image.draggable = false;
      art.appendChild(image);
      if (current.mode === 'page') {
        var targets = el('div','panel-targets');
        page.panels.forEach(function (panel,index) {
          var target = button('', 'panel-target', function () { go(copy(current,{panel:index+1,mode:'panel'}),false); });
          target.setAttribute('aria-label','Read panel ' + (index+1) + ': ' + panel.alt);
          target.setAttribute('data-panel-target',String(index+1));
          targets.appendChild(target);
        });
        art.appendChild(targets);
      }
      var touch;
      art.addEventListener('touchstart',function (event) {
        if (event.touches.length === 1) touch = {x:event.touches[0].clientX,y:event.touches[0].clientY};
      },{passive:true});
      art.addEventListener('touchend',function (event) {
        if (!touch || event.changedTouches.length !== 1) return;
        var dx = event.changedTouches[0].clientX - touch.x;
        var dy = event.changedTouches[0].clientY - touch.y;
        touch = null;
        if (Math.abs(dx) > 65 && Math.abs(dx) > Math.abs(dy) * 1.5) advance(dx < 0 ? 1 : -1);
      },{passive:true});
      stage.appendChild(art);
      stage.appendChild(el('p','art-hint',current.mode === 'page' ? 'Tap a panel to read it closely.' : 'Swipe the picture, or use Previous and Next.'));
      if (current.mode === 'panel') stage.appendChild(panelText(page.panels[current.panel-1],current.panel,false));
      else {
        var all = el('div','full-page-text');
        page.panels.forEach(function (panel,index) { all.appendChild(panelText(panel,index+1,true)); });
        stage.appendChild(all);
      }
      var turnViewport = el('div','turn-viewport');
      turnViewport.appendChild(stage);
      out.appendChild(turnViewport);
    }
    var controls = el('nav','page-controls');
    controls.setAttribute('aria-label','Story navigation');
    var prev = button('Previous','previous',function () { advance(-1); });
    prev.setAttribute('data-previous','');
    prev.disabled = !current.end && current.page === 1 && (current.mode === 'page' || current.panel === 1);
    var ending = current.page === c.pages.length && (current.mode === 'page' || current.panel === 6);
    var next = button(ending ? 'Finish chapter' : 'Next','next',function () { advance(1); });
    next.setAttribute('data-next','');
    next.disabled = current.end;
    var mini = el('span','mini-position',current.mode === 'panel' ? current.panel + ' / 6' : current.page + ' / ' + c.pages.length);
    mini.setAttribute('aria-hidden','true');
    append(controls,prev,mini,next);out.appendChild(controls);
    return out;
  }
  function fitOverview() {
    var frame = root.querySelector('.art-frame.mode-page');
    var controls = root.querySelector('.page-controls');
    if (!frame || !controls) return;
    // Unlike CSS min()/aspect-ratio, explicit measured sizing also works in
    // the older WebView shipped on the Android8 test fixture.
    frame.style.width = '';
    frame.style.height = '';
    var rect = frame.getBoundingClientRect();
    var available = Math.max(0, window.innerHeight - rect.top - controls.offsetHeight - 4);
    var width = Math.max(0, Math.min(rect.width, Math.floor(available * 2 / 3)));
    frame.style.width = width + 'px';
    frame.style.height = Math.floor(width * 3 / 2) + 'px';
  }
  function render() {
    if (!catalog) return;
    current = parse();
    // Browser/native Back can reach the original bare library entry. Preserve
    // its in-memory reading shortcut in the URL before a tab switch/recreation.
    if (current.screen === 'library' && !current.chapter && last && last.chapter) {
      current = copy(last,{screen:'library'});
      history.replaceState(null,'',url(current));
    }
    if (current.chapter) last = copy(current,{});
    root.textContent = '';
    root.appendChild(current.screen === 'read' ? reading() : library());
    root.setAttribute('aria-busy','false');
    pendingTurn = 0;
    window.scrollTo(0,0);
    fitOverview();
    requestAnimationFrame(fitOverview);
  }
  window.addEventListener('hashchange',render);
  window.addEventListener('resize',fitOverview);
  document.addEventListener('keydown',function (event) {
    if (!current || current.screen !== 'read' || event.altKey || event.ctrlKey || event.metaKey || /INPUT|TEXTAREA|SELECT/.test(event.target.tagName)) return;
    if (event.key === 'ArrowRight' && !current.end) { event.preventDefault(); advance(1); }
    if (event.key === 'ArrowLeft') { event.preventDefault(); advance(-1); }
  });
  fetch('catalog.json',{credentials:'omit'}).then(function (response) {
    if (!response.ok) throw new Error('Story catalog is unavailable');
    return response.json();
  }).then(function (data) {
    catalog = data;
    if (catalog.schema !== 1 || !catalog.world || catalog.world.id !== 'persia' || catalog.chapters.length !== 2) throw new Error('Story catalog needs an update');
    render();
  }).catch(function () {
    root.textContent = '';
    root.appendChild(el('p','error','The offline story could not open. Return to Stories, or install the latest Rookstride update.'));
    root.setAttribute('aria-busy','false');
  });
}());
