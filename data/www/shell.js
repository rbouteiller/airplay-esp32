/* The frame every page shares: tabs along the top, the status strip, the restart
   banner and the log drawer. A page loads it as the first thing in <body>,
   so the frame is in place before the page's own content is parsed and
   nothing moves when it fills in. Pages reach it through window.Shell. */
(function(){
'use strict';

var CSS=
'html.sh{--sh-bottom:0px}'+
'html.sh-logs{--sh-bottom:42vh}'+
'.sh-nav{display:flex;flex-wrap:wrap;align-items:flex-end;gap:0 4px;'+
  'margin:-4px 0 14px;border-bottom:1px solid rgba(255,255,255,0.12);'+
  'font:14px -apple-system,system-ui,sans-serif;color:#fff}'+
'.sh-dev{display:flex;align-items:baseline;gap:8px;min-width:0;'+
  'padding:0 20px 10px 2px}'+
'.sh-dev b{font-size:16px;font-weight:600;overflow-wrap:anywhere}'+
'.sh-dev span{font-size:12px;color:#888;white-space:nowrap}'+
'.sh-nav a,.sh-nav button{padding:9px 14px 10px;margin-bottom:-1px;border:0;'+
  'border-bottom:2px solid transparent;background:none;color:#bbb;font:inherit;'+
  'text-decoration:none;white-space:nowrap;cursor:pointer}'+
'.sh-nav a:hover,.sh-nav button:hover{color:#fff}'+
'.sh-nav a.on,.sh-nav button.on{color:#fff;border-bottom-color:#e94560}'+
'.sh-nav a[hidden]{display:none}'+
'.sh-nav .sh-gap{flex:1}'+
'.sh-strip{display:flex;flex-wrap:wrap;align-items:center;gap:8px 20px;'+
  'padding:10px 14px;margin-bottom:16px;border-radius:12px;'+
  'background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.08);'+
  'font:13px -apple-system,system-ui,sans-serif;color:#ccc}'+
'.sh-net{display:flex;align-items:center;gap:8px;white-space:nowrap}'+
'.sh-dot{width:9px;height:9px;border-radius:50%;background:#666;flex:none}'+
'.sh-dot.ok{background:#3fb950}.sh-dot.warn{background:#d29922}.sh-dot.err{background:#f85149}'+
'.sh-play{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'+
'.sh-play b{color:#fff;font-weight:500}'+
'.sh-vol{display:flex;align-items:center;gap:8px;white-space:nowrap}'+
'.sh-vol input{accent-color:#e94560;width:140px;max-width:none;margin:0}'+
'.sh-vol .sh-vl{color:#888}'+
'.sh-vol .sh-vv{min-width:58px;text-align:right;color:#fff}'+
'.sh-vol[hidden]{display:none}'+
'.sh-banner{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;'+
  'padding:10px 14px;margin-bottom:16px;border-radius:12px;'+
  'background:rgba(233,69,96,0.14);border:1px solid rgba(233,69,96,0.6);'+
  'font:13px -apple-system,system-ui,sans-serif;color:#fff}'+
'.sh-banner[hidden]{display:none}'+
'.sh-banner span{flex:1;min-width:200px}'+
'.sh-banner button{padding:8px 14px;border:0;border-radius:8px;background:#e94560;'+
  'color:#fff;font:500 13px -apple-system,system-ui,sans-serif;cursor:pointer}'+
'.sh-banner button:disabled{opacity:0.5;cursor:default}'+
'.sh-tick{font-size:12px;margin-left:10px;white-space:nowrap}'+
'.sh-tick.ok{color:#3fb950}.sh-tick.err{color:#ff7b72;white-space:normal}'+
'.sh-drawer{position:fixed;left:0;right:0;bottom:0;height:42vh;z-index:30;'+
  'display:none;flex-direction:column;background:#0d1117;color:#c9d1d9;'+
  'border-top:1px solid #30363d;font:12px -apple-system,system-ui,sans-serif}'+
'html.sh-logs .sh-drawer{display:flex}'+
'html.sh-logs body{padding-bottom:calc(42vh + 20px)}'+
'.sh-dh{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px;padding:6px 10px;'+
  'background:#161b22;border-bottom:1px solid #30363d}'+
'.sh-dh b{font-size:13px;font-weight:600;margin-right:4px}'+
'.sh-dh .sh-gap{flex:1}'+
'.sh-dh select,.sh-dh input,.sh-dh button,.sh-dh a{width:auto;min-width:0;margin:0;'+
  'padding:4px 8px;border:1px solid #30363d;'+
  'border-radius:6px;background:#21262d;color:#c9d1d9;font:12px -apple-system,system-ui,sans-serif;'+
  'text-decoration:none;cursor:pointer}'+
'.sh-dh input{width:150px;cursor:text}'+
'.sh-dh button.on{background:#1f6feb;border-color:#1f6feb;color:#fff}'+
'.sh-dl{flex:1;min-height:0;overflow-y:auto;padding:6px 10px;'+
  "font:12px/1.5 'SF Mono',Consolas,monospace;white-space:pre-wrap;word-break:break-all}"+
'.sh-dl div[hidden]{display:none}'+
'.sh-lE{color:#f85149}.sh-lW{color:#d29922}.sh-lI{color:#3fb950}.sh-lD,.sh-lV{color:#6e7681}'+
'@media (max-width:759px){'+
  '.sh-dev{flex-basis:100%;padding-bottom:4px}'+
  '.sh-nav a,.sh-nav button{padding:9px 10px 10px}'+
  '.sh-vol{flex-basis:100%}'+
  '.sh-vol input{flex:1;width:auto}'+
  '.sh-play{flex-basis:100%}'+
  'html.sh-logs{--sh-bottom:55vh}'+
  '.sh-drawer{height:55vh}'+
  'html.sh-logs body{padding-bottom:calc(55vh + 20px)}'+
'}';

var root=document.documentElement;
var style=document.createElement('style');
style.textContent=CSS;
document.head.appendChild(style);
root.classList.add('sh');

function el(tag,cls,text){
  var e=document.createElement(tag);
  if(cls)e.className=cls;
  if(text!=null)e.textContent=text;
  return e;
}
function store(kind,key,val){
  try{
    var s=kind==='session'?sessionStorage:localStorage;
    if(val===undefined)return s.getItem(key);
    if(val===null)s.removeItem(key);else s.setItem(key,val);
  }catch(e){}
  return null;
}
function db(v){return (v<0?'−':'')+Math.abs(v).toFixed(1)+' dB';}

/* ---- requests ----
   The device serves three sockets at most (two with Bluetooth), and the page
   uses them too, so the shell's requests and those the pages send through
   Shell.get/post go one at a time. */
var queue=Promise.resolve();
function request(url,opts){
  var p=queue.then(function(){
    return fetch(url,opts).then(function(r){
      return r.text().then(function(t){return {r:r,t:t};});
    });
  });
  queue=p.then(function(){},function(){});
  return p.then(function(x){
    var d=null;
    try{d=x.t?JSON.parse(x.t):null;}catch(e){}
    if(!x.r.ok){
      var err=new Error((d&&d.error)||x.t||('HTTP '+x.r.status));
      err.status=x.r.status;err.data=d;throw err;
    }
    return d;
  });
}
function get(url){return request(url,{cache:'no-store'});}
function post(url,body){
  var o={method:'POST'};
  if(body!==undefined){
    o.headers={'Content-Type':'application/json'};
    o.body=JSON.stringify(body);
  }
  return request(url,o);
}

var infoP=null;
function info(){
  if(!infoP){
    infoP=get('/api/system/info').then(function(d){return d.info;});
    infoP.catch(function(){infoP=null;});
  }
  return infoP;
}

/* ---- frame ----
   Tabs across the top: the device's name, a tab per page, and Logs. */
var path=location.pathname.replace(/\/+$/,'')||'/';
var here={'/config':'/','/speedtest':'/network','/hf':'/bq'}[path]||path;

var nav=el('nav','sh-nav');
var dev=el('div','sh-dev');
var devName=el('b',null,' ');
var devSub=el('span',null,' ');
dev.appendChild(devName);dev.appendChild(devSub);
nav.appendChild(dev);
var links={};
[['/','Speaker'],['/network','Network'],['/bq','Equaliser']]
.forEach(function(p){
  var a=el('a',p[0]===here?'on':null,p[1]);
  a.href=p[0];
  // Only boards with an equaliser show it; that is known once info arrives.
  if(p[0]==='/bq'&&here!=='/bq')a.hidden=true;
  links[p[0]]=a;
  nav.appendChild(a);
});
nav.appendChild(el('div','sh-gap'));
var logsBtn=el('button',null,'Logs');
logsBtn.type='button';
nav.appendChild(logsBtn);

var strip=el('div','sh-strip');
var net=el('span','sh-net');
var netDot=el('i','sh-dot');
var netText=el('span',null,'Connecting…');
net.appendChild(netDot);net.appendChild(netText);
var play=el('span','sh-play');
var vol=el('label','sh-vol');
vol.appendChild(el('span','sh-vl','Volume'));
var volRange=el('input');volRange.type='range';volRange.step='0.5';
var volVal=el('span','sh-vv','');
vol.appendChild(volRange);vol.appendChild(volVal);
vol.hidden=true;
strip.appendChild(net);strip.appendChild(play);
strip.appendChild(vol);

var banner=el('div','sh-banner');
banner.hidden=true;
var bannerText=el('span');
var bannerBtn=el('button',null,'Restart now');
bannerBtn.type='button';
banner.appendChild(bannerText);banner.appendChild(bannerBtn);

var body=document.body;
body.appendChild(nav);
body.appendChild(strip);
body.appendChild(banner);

info().then(function(i){
  if(i.eq_supported||i.sub_supported){links['/bq'].hidden=false;}
  else if(i.hf1_supported||i.hf3_supported){
    links['/bq'].href='/hf';links['/bq'].hidden=false;
  }
  if(i.firmware_version)devSub.textContent=i.firmware_version;
}).catch(function(){});

/* ---- volume ----
   One value shown by every slider bound to it: the strip's and any a page
   adds with Shell.volume(). */
var volume={db:null,min:-30,max:0,muted:false,busy:false};
var volBound=[];
function showVolume(){
  volBound.forEach(function(b){
    b.range.min=volume.min;b.range.max=volume.max;
    if(!volume.busy)b.range.value=volume.db;
    b.label.textContent=volume.muted?'Muted':db(Number(b.range.value));
  });
}
function bindVolume(range,label){
  var b={range:range,label:label};
  volBound.push(b);
  range.addEventListener('input',function(){
    volume.busy=true;
    label.textContent=db(Number(range.value));
  });
  range.addEventListener('change',function(){
    volume.db=Number(range.value);
    volume.busy=false;
    showVolume();
    post('/api/audio/volume',{volume_db:volume.db,persist:true})
      .catch(function(){refresh();});
  });
  if(volume.db!=null)showVolume();
  return b;
}
bindVolume(volRange,volVal);

/* ---- status ---- */
var SOURCES={airplay:'AirPlay',bluetooth:'Bluetooth',usb:'USB',sendspin:'Sendspin'};
var listeners=[];
var last=null;
var legacy=false;
var pollTimer=0;
var restarting=false;

function fromInfo(i){
  return {name:i.device_name,ip:i.ip,rssi:i.wifi_rssi,
          link:i.eth_connected?'ethernet':i.wifi_connected?'wifi':'none',
          source:'',state:'idle',restart:[],legacy:true};
}
function render(s){
  devName.textContent=s.name||' ';
  if(s.name)document.title=document.title.replace(/ - .*$/,'')+' - '+s.name;
  var t,c;
  if(s.link==='ethernet'){t='Ethernet · '+s.ip;c='ok';}
  else if(s.link==='wifi'){
    t='Wi-Fi · '+s.ip+(s.rssi!=null?' · '+s.rssi+' dBm':'');
    c=s.rssi!=null&&s.rssi<-75?'warn':'ok';
  }else{t='Not on a network yet';c='err';}
  netText.textContent=t;netDot.className='sh-dot '+c;

  play.textContent='';
  if(s.legacy){/* old firmware: no now-playing to show */}
  else if(s.source){
    var src=SOURCES[s.source]||s.source;
    var what=[s.artist,s.title].filter(Boolean).join(' – ');
    play.appendChild(document.createTextNode(
      (s.state==='playing'?'▶ ':'‖ ')+src+(what?' · ':'')));
    if(what)play.appendChild(el('b',null,what));
    if(s.state!=='playing')play.appendChild(document.createTextNode(' (paused)'));
    play.title=what;
  }else{
    play.textContent='Nothing playing';
    play.title='';
  }

  if(typeof s.volume_db==='number'){
    volume.db=s.volume_db;volume.min=s.volume_min;volume.max=s.volume_max;
    volume.muted=!!s.muted;vol.hidden=false;showVolume();
  }

  var r=s.restart||[];
  if(!restarting){
    banner.hidden=!r.length;
    bannerText.textContent=(r.length===1?'One change waits':r.length+' changes wait')+
      ' for a restart: '+r.join(', ')+'.';
  }
}
function offline(){
  netText.textContent='The device is not answering';
  netDot.className='sh-dot err';
}
function refresh(){
  return get(legacy?'/api/system/info':'/api/status').then(function(d){
    var s=legacy?fromInfo(d.info):d;
    last=s;render(s);
    listeners.forEach(function(fn){try{fn(s);}catch(e){console.error(e);}});
    return s;
  },function(e){
    // Firmware older than these pages has no /api/status.
    if(e.status===404&&!legacy){legacy=true;return refresh();}
    offline();
    throw e;
  });
}
function schedule(){
  clearTimeout(pollTimer);
  if(document.hidden||restarting)return;
  pollTimer=setTimeout(function(){
    refresh().then(schedule,schedule);
  },legacy?30000:5000);
}
document.addEventListener('visibilitychange',function(){
  if(!document.hidden&&!restarting)refresh().then(schedule,schedule);
  else clearTimeout(pollTimer);
});
refresh().then(schedule,schedule);

/* ---- restart ---- */
function waitForRestart(text){
  restarting=true;
  clearTimeout(pollTimer);
  banner.hidden=false;
  bannerBtn.disabled=true;
  bannerText.textContent=text||'Restarting…';
  var t0=Date.now();
  function probe(){
    fetch(legacy?'/api/system/info':'/api/status',{cache:'no-store'})
      .then(function(r){if(r.ok)location.reload();else throw 0;})
      .catch(function(){
        if(Date.now()-t0<120000)setTimeout(probe,2000);
        else bannerText.textContent=
          'Still not answering. Reload the page when the device is back.';
      });
  }
  // Give it time to go down first, or the old firmware answers the probe.
  setTimeout(probe,5000);
}
function restart(){
  if(!confirm('Restart the device now? Playback stops until it is back, '+
              'in about 15 seconds.'))return;
  post('/api/system/restart').catch(function(){});
  waitForRestart('Restarting… the page reloads when the device is back.');
}
bannerBtn.onclick=restart;

/* ---- feedback ----
   The one save model: a control applies when changed, and a tick beside it
   says whether that worked. */
function tick(target,ok,text){
  var t=target._shTick;
  if(!t){
    t=el('span','sh-tick');
    target.insertAdjacentElement('afterend',t);
    target._shTick=t;
  }
  clearTimeout(t._h);
  t.className='sh-tick '+(ok?'ok':'err');
  t.textContent=(ok?'✓ ':'✗ ')+(text||(ok?'Saved':'Not saved'));
  if(ok)t._h=setTimeout(function(){t.textContent='';},3000);
}

/* ---- log drawer ----
   The /ws/logs stream in a drawer over any page, with level and tag
   filters. It holds a socket only while open. */
var drawer=el('div','sh-drawer');
var dh=el('div','sh-dh');
var dDot=el('i','sh-dot');
var lvlSel=el('select');
[['5','All levels'],['3','Info and up'],['2','Warnings and up'],['1','Errors only']]
.forEach(function(o){var op=el('option',null,o[1]);op.value=o[0];lvlSel.appendChild(op);});
var tagIn=el('input');
tagIn.placeholder='Tags: wifi, -rtsp';
tagIn.title='Show only these tags (comma separated); a leading - hides a tag';
var followBtn=el('button','on','Follow');followBtn.type='button';
var clearBtn=el('button',null,'Clear');clearBtn.type='button';
var fullA=el('a',null,'Full screen');fullA.href='/logs';
var closeBtn=el('button',null,'✕');closeBtn.type='button';closeBtn.title='Close';
dh.appendChild(el('b',null,'Logs'));dh.appendChild(dDot);
dh.appendChild(lvlSel);dh.appendChild(tagIn);dh.appendChild(el('span','sh-gap'));
dh.appendChild(followBtn);dh.appendChild(clearBtn);dh.appendChild(fullA);
dh.appendChild(closeBtn);
var dl=el('div','sh-dl');
drawer.appendChild(dh);drawer.appendChild(dl);
body.appendChild(drawer);

var LEVELS={E:1,W:2,I:3,D:4,V:5};
var MAX_LINES=1500;
var lines=[];
var partial='';
var prev={lvl:'I',tag:''};
var follow=true;
var ws=null;
var wsTimer=0;
var filt={max:5,inc:[],exc:[]};

function parseFilter(){
  filt.max=Number(lvlSel.value)||5;
  filt.inc=[];filt.exc=[];
  tagIn.value.split(',').forEach(function(t){
    t=t.trim().toLowerCase();
    if(!t)return;
    if(t.charAt(0)==='-'){if(t.length>1)filt.exc.push(t.slice(1));}
    else filt.inc.push(t);
  });
  store('local','sh-log-filter',JSON.stringify({l:lvlSel.value,t:tagIn.value}));
}
function shown(e){
  if(LEVELS[e.lvl]>filt.max)return false;
  var tag=e.tag.toLowerCase();
  function has(t){return tag.indexOf(t)>=0;}
  if(filt.inc.length&&!filt.inc.some(has))return false;
  return !filt.exc.some(has);
}
function refilter(){
  parseFilter();
  lines.forEach(function(e){e.node.hidden=!shown(e);});
  if(follow)dl.scrollTop=dl.scrollHeight;
}
function atBottom(){return dl.scrollHeight-dl.scrollTop-dl.clientHeight<40;}
function setFollow(v){follow=v;followBtn.classList.toggle('on',v);}

function addText(text){
  text=partial+text;
  var cut=text.lastIndexOf('\n');
  partial=cut<0?text:text.slice(cut+1);
  if(cut<0)return;
  var frag=document.createDocumentFragment();
  text.slice(0,cut).split('\n').forEach(function(raw){
    var line=raw.replace(/\x1b\[[0-9;]*m/g,'').replace(/\r$/,'');
    if(!line)return;
    var m=/^([EWIDV]) \(\d+\) ([^:]*):/.exec(line);
    // A line without the prefix continues the one before it.
    if(m)prev={lvl:m[1],tag:m[2]};
    var e={lvl:prev.lvl,tag:prev.tag,node:el('div','sh-l'+prev.lvl,line)};
    e.node.hidden=!shown(e);
    lines.push(e);
    frag.appendChild(e.node);
  });
  dl.appendChild(frag);
  while(lines.length>MAX_LINES){dl.removeChild(lines.shift().node);}
  if(follow)dl.scrollTop=dl.scrollHeight;
}
function connect(){
  clearTimeout(wsTimer);
  ws=new WebSocket('ws://'+location.host+'/ws/logs');
  ws.onopen=function(){dDot.className='sh-dot ok';};
  ws.onmessage=function(e){addText(e.data);};
  ws.onclose=function(){
    dDot.className='sh-dot err';
    ws=null;
    if(root.classList.contains('sh-logs'))wsTimer=setTimeout(connect,2000);
  };
}
function openLogs(open){
  root.classList.toggle('sh-logs',open);
  logsBtn.classList.toggle('on',open);
  store('session','sh-logs',open?'1':null);
  if(open){if(!ws)connect();if(follow)dl.scrollTop=dl.scrollHeight;}
  else{
    clearTimeout(wsTimer);
    if(ws){var w=ws;ws=null;w.onclose=null;w.close();}
    dDot.className='sh-dot';
  }
  // Pages with canvases size them to their box.
  window.dispatchEvent(new Event('resize'));
}
logsBtn.onclick=function(){openLogs(!root.classList.contains('sh-logs'));};
closeBtn.onclick=function(){openLogs(false);};
clearBtn.onclick=function(){lines=[];dl.textContent='';};
followBtn.onclick=function(){
  setFollow(!follow);
  if(follow)dl.scrollTop=dl.scrollHeight;
};
// Scrolling up to read stops the lines arriving from pulling the view down;
// scrolling back to the end follows again.
dl.addEventListener('scroll',function(){
  if(follow&&!atBottom())setFollow(false);
  else if(!follow&&atBottom())setFollow(true);
});
lvlSel.onchange=refilter;
tagIn.oninput=refilter;
try{
  var f=JSON.parse(store('local','sh-log-filter')||'null');
  if(f){lvlSel.value=f.l;tagIn.value=f.t;}
}catch(e){}
parseFilter();
if(store('session','sh-logs')==='1')openLogs(true);

window.Shell={
  get:get,
  post:post,
  info:info,
  refresh:refresh,
  last:function(){return last;},
  onStatus:function(fn){listeners.push(fn);if(last)fn(last);},
  volume:bindVolume,
  restart:restart,
  waitForRestart:waitForRestart,
  tick:tick,
  db:db,
  el:el
};
})();
