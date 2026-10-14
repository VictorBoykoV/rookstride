(function(){
 'use strict';
 var names={en:'English',ru:'Русский',fa:'فارسی',ar:'العربية','zh-Hans':'简体中文'};
 var hints=/* translated-hints */null;
 var route=document.body.getAttribute('data-route')||'/',current=document.documentElement.lang||'en';
 function supported(tag){var value=(tag||'').toLowerCase();if(/^zh-hans(?:-|$)/.test(value))return 'zh-Hans';if(/^zh(?:$|-cn|-sg)/.test(value)&&!/-hant|-tw|-hk|-mo/.test(value))return 'zh-Hans';var base=value.split('-')[0];return names[base]?base:'en';}
 function preference(){try{return localStorage.getItem('rookstride-language')||'';}catch(e){return '';}}
 var links=document.querySelectorAll('[data-language][href]');
 for(var i=0;i<links.length;i++)links[i].addEventListener('click',function(){try{localStorage.setItem('rookstride-language',this.getAttribute('data-language'));}catch(e){}});
 if(current!=='en'||preference()==='en'||['/','/start/','/architecture/','/routes/','/download/','/open-source/','/rook/','/worlds/','/plans/'].indexOf(route)<0)return;
 var desired=preference()?supported(preference()):'en',languages=navigator.languages||[navigator.language];
 if(!preference())for(var n=0;n<languages.length;n++){desired=supported(languages[n]);if(desired!=='en')break;}
 if(desired==='en')return;
 var target=document.querySelector('a[data-language="'+desired+'"]');if(!target)return;
 var hint=document.createElement('aside');hint.className='language-suggestion';hint.setAttribute('aria-label','Language suggestion');
 var text=document.createElement('span');text.lang=desired;text.dir='auto';text.textContent=(preference()?hints[desired].chosen:hints[desired].hint).replace('{language}',names[desired]);hint.appendChild(text);
 var open=document.createElement('a');open.className='button outline';open.lang=desired;open.textContent=names[desired];open.href=target.getAttribute('href');open.addEventListener('click',function(){try{localStorage.setItem('rookstride-language',desired);}catch(e){}});hint.appendChild(open);
 var keep=document.createElement('button');keep.type='button';keep.textContent=hints[desired].keep;keep.addEventListener('click',function(){try{localStorage.setItem('rookstride-language','en');}catch(e){}hint.parentNode.removeChild(hint);});hint.appendChild(keep);
 var main=document.getElementById('main');if(main)main.insertBefore(hint,main.firstChild);
})();
