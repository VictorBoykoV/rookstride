/* Narration is opt-in. No next-chapter auto-play, fetch, trackers or saved secrets. */
(() => {
  'use strict';
  const reader=document.querySelector('[data-story-reader]'); if(!reader)return;
  const pages=[...reader.querySelectorAll('.story-page')],stage=reader.querySelector('.story-pages');
  const play=reader.querySelector('[data-narrate]'),stopButton=reader.querySelector('[data-voice-stop]'),voices=reader.querySelector('[data-voices]'),rate=reader.querySelector('[data-rate]');
  const voiceStatus=reader.querySelector('.voice-status'),status=reader.querySelector('[data-story-status]'),finished=reader.querySelector('.chapter-finished');
  const native=typeof window.RookVoice==='object',supported=native||('speechSynthesis' in window&&'SpeechSynthesisUtterance' in window);
  const readingId=Date.now().toString(36)+'_'+Math.random().toString(36).slice(2,10);
  let page=0,mode='page',playing=false,paused=false,generation=0,utterance=null,motion=!matchMedia('(prefers-reduced-motion: reduce)').matches,voiceList=[];
  reader.classList.add('enhanced');reader.dataset.mode=mode;
  function plain(p){return p.querySelector('.narration').dataset.original||p.querySelector('.narration').textContent;}
  pages.forEach(p=>{p.querySelector('.narration').dataset.original=p.querySelector('.narration').textContent;});
  function clearHighlight(){pages.forEach(p=>{p.classList.remove('narrating');p.querySelector('.narration').textContent=plain(p);});}
  function render(animate=false){
    pages.forEach((p,i)=>{p.classList.toggle('current',i===page);p.classList.remove('turning');});
    if(mode==='chapter'&&playing)pages[page].scrollIntoView({behavior:motion?'smooth':'auto',block:'start'});
    if(animate&&motion){void pages[page].offsetWidth;pages[page].classList.add('turning');}
    finished.hidden=playing||paused||(mode==='page'&&page<pages.length-1);
    reader.dataset.mode=mode;status.textContent=`Page ${page+1} / ${pages.length}`;
    reader.querySelector('[data-story-prev]').disabled=page===0;reader.querySelector('[data-story-next]').disabled=page===pages.length-1;
    reader.querySelectorAll('[data-story-mode]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.storyMode===mode)));
    reader.querySelector('[data-story-motion]').setAttribute('aria-pressed',String(motion));reader.querySelector('[data-story-motion]').textContent=motion?'Page turns on':'Page turns off';
    play.textContent=paused?'▶ Resume narration':playing?'Ⅱ Pause narration':'▶ Listen to this chapter';stopButton.disabled=!playing&&!paused;
    history.replaceState(null,'',`#page-${page+1}`);
  }
  function cancel(){generation++;playing=false;paused=false;if(native)window.RookVoice.stop();else if(supported)window.speechSynthesis.cancel();utterance=null;clearHighlight();render();}
  function highlight(start,end){const p=pages[page],target=p.querySelector('.narration'),text=plain(p);p.classList.add('narrating');if(start>=text.length)return;target.textContent='';target.append(document.createTextNode(text.slice(0,start)));const mark=document.createElement('mark');const boundaryEnd=end>start?end:text.indexOf(' ',start);mark.textContent=text.slice(start,boundaryEnd>start?boundaryEnd:text.length);target.append(mark,document.createTextNode(text.slice(start+mark.textContent.length)));}
  function loadVoices(){
    try{voiceList=native?JSON.parse(window.RookVoice.voices()):supported?window.speechSynthesis.getVoices().filter(v=>/^en(?:-|$)/i.test(v.lang)):[];}catch(error){voiceList=[];}
    voices.textContent='';if(!voiceList.length){const opt=document.createElement('option');opt.textContent='No English device voice available';voices.append(opt);play.disabled=true;voiceStatus.textContent=supported?'Install an English voice in your device speech settings, then reopen or retry. Android uses installed offline voices.':'This browser has no device narration. The complete story remains readable.';return;}
    voiceList.sort((a,b)=>Number(b.localService)-Number(a.localService));voiceList.forEach((v,i)=>{const opt=document.createElement('option');opt.value=String(i);opt.textContent=`${v.name} (${v.lang}${v.localService?' · on device':' · may use network'})`;voices.append(opt);});play.disabled=false;voiceStatus.textContent='Device voice ready. Listen turns pages, and stops at the chapter’s end.';
  }
  function speakPage(){
    if(!playing)return;const token=readingId+'_'+String(generation)+'_'+String(page),text=plain(pages[page]);clearHighlight();pages[page].classList.add('narrating');
    const complete=()=>{if(!playing||token!==readingId+'_'+String(generation)+'_'+String(page))return;clearHighlight();if(page+1<pages.length){page++;render(true);speakPage();}else{playing=false;paused=false;finished.hidden=false;voiceStatus.textContent='Chapter complete. Choose the next chapter when you are ready.';render();}};
    const error=()=>{if(token!==readingId+'_'+String(generation)+'_'+String(page))return;cancel();voiceStatus.textContent='The device voice could not finish. Check its speech settings; you can keep reading.';};
    if(native){window.rookNarrationEvent=(id,event,start,end)=>{if(id!==token||!playing)return;if(event==='end')complete();else if(event==='error')error();else if(event==='boundary')highlight(start,end);};window.RookVoice.speak(token,text,(voiceList[Number(voices.value)]||{}).name||'',Number(rate.value));}
    else{utterance=new SpeechSynthesisUtterance(text);utterance.voice=voiceList[Number(voices.value)]||null;utterance.lang='en';utterance.rate=Number(rate.value);utterance.onboundary=e=>{if(playing&&token===readingId+'_'+String(generation)+'_'+String(page))highlight(e.charIndex,e.charIndex+(e.charLength||0));};utterance.onend=complete;utterance.onerror=error;window.speechSynthesis.speak(utterance);}
    render();
  }
  play.addEventListener('click',()=>{if(playing){if(native)window.RookVoice.stop();else window.speechSynthesis.cancel();generation++;playing=false;paused=true;clearHighlight();voiceStatus.textContent='Paused. Resume restarts this page.';render();return;}if(!finished.hidden){page=0;render(true);}playing=true;paused=false;generation++;finished.hidden=true;voiceStatus.textContent='Reading this chapter. You can stop or turn a page at any time.';speakPage();});
  stopButton.addEventListener('click',()=>{cancel();voiceStatus.textContent='Narration stopped.';});
  function turn(delta){cancel();page=Math.max(0,Math.min(pages.length-1,page+delta));finished.hidden=true;render(true);}
  reader.querySelector('[data-story-prev]').addEventListener('click',()=>turn(-1));reader.querySelector('[data-story-next]').addEventListener('click',()=>turn(1));
  reader.querySelectorAll('[data-story-mode]').forEach(b=>b.addEventListener('click',()=>{mode=b.dataset.storyMode;render();}));
  reader.querySelector('[data-story-motion]').addEventListener('click',()=>{motion=!motion;render();});
  stage.addEventListener('keydown',e=>{if(e.key==='ArrowRight'||e.key==='ArrowLeft'){e.preventDefault();turn(e.key==='ArrowRight'?1:-1);}});
  let pointer=null;stage.addEventListener('pointerdown',e=>{if(e.isPrimary)pointer={x:e.clientX,y:e.clientY};});stage.addEventListener('pointercancel',()=>{pointer=null;});stage.addEventListener('pointerup',e=>{if(!pointer)return;const dx=e.clientX-pointer.x,dy=e.clientY-pointer.y;pointer=null;if(Math.abs(dx)>55&&Math.abs(dx)>Math.abs(dy)*1.5)turn(dx<0?1:-1);});
  voices.addEventListener('change',()=>{if(playing||paused)cancel();});rate.addEventListener('change',()=>{if(playing||paused)cancel();});
  document.addEventListener('visibilitychange',()=>{if(document.hidden&&(playing||paused)){cancel();voiceStatus.textContent='Narration stopped while the page was hidden.';}});
  window.rookStopNarration=cancel;
  window.addEventListener('pagehide',cancel);
  if(!native&&supported)window.speechSynthesis.addEventListener('voiceschanged',loadVoices);
  const match=location.hash.match(/^#page-(\d+)$/);if(match)page=Math.max(0,Math.min(pages.length-1,Number(match[1])-1));
  render();loadVoices();if(native){let retries=0;const timer=setInterval(()=>{if(voiceList.length||++retries>8)clearInterval(timer);else loadVoices();},500);}
})();
