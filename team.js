/* SkyMorph team layer: passcode gate, shared serial numbers and team documents.
   There is no server. Shared state lives in a private GitHub repository, reached with
   an access key that is stored encrypted in team-config.js and only the passcode unlocks. */
(function(){
'use strict';
var VERIFY='422fb0f1821013472721ac604048d62471ccefb6aaa14a517e101828a9af16e0';
var KEY_SALT='skymorph-team-key-v1',ITER=300000,LS='skymorph:teamkey';
var TYPE=window.TEAM_TYPE||'',NEWFN=window.TEAM_NEW||'';
var NAMES={quotation:'Quotations',proforma:'Proforma invoices',invoice:'Tax invoices'};
var CAN_OPEN={quotation:['quotation'],proforma:['proforma','quotation','invoice'],invoice:['invoice','quotation']};
var DEF={quotation:'SM/QTN/{FY}/000',proforma:'SM/PI/{FY}/000',invoice:'SM/INV/{FY}/000'};
var token=null,known='',chip=null;
var te=new TextEncoder(),td=new TextDecoder();
function cfg(){return window.TEAM_CONFIG||null;}

/* ---------- small helpers ---------- */
function b64(buf){var b=new Uint8Array(buf),s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
function unb64(s){var b=atob(String(s).replace(/\s/g,'')),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}
function hex(buf){var b=new Uint8Array(buf),s='';for(var i=0;i<b.length;i++)s+=(b[i]<16?'0':'')+b[i].toString(16);return s;}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function safe(no){return String(no).trim().replace(/[^\w.-]+/g,'_');}
function wait(ms){return new Promise(function(r){setTimeout(r,ms);});}
function el(id){return document.getElementById(id);}

/* ---------- passcode ---------- */
function derive(pass){
  return crypto.subtle.importKey('raw',te.encode(pass),'PBKDF2',false,['deriveBits']).then(function(km){
    return crypto.subtle.deriveBits({name:'PBKDF2',salt:te.encode(KEY_SALT),iterations:ITER,hash:'SHA-256'},km,256);
  }).then(function(bits){return new Uint8Array(bits);});
}
function check(raw){
  var v=new Uint8Array(raw.length+6);v.set(raw);v.set(te.encode('verify'),raw.length);
  return crypto.subtle.digest('SHA-256',v).then(function(h){return hex(h)===VERIFY;});
}
function aes(raw,use){return crypto.subtle.importKey('raw',raw,'AES-GCM',false,[use]);}
function openToken(raw){
  var c=cfg();
  if(!c||!c.enc)return Promise.resolve(null);
  return aes(raw,'decrypt').then(function(k){
    return crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(c.enc.iv)},k,unb64(c.enc.ct));
  }).then(function(pt){return td.decode(pt);});
}
/* used by setup.html: lock an access key with the passcode */
function seal(pass,secret){
  return derive(pass).then(function(raw){
    return check(raw).then(function(ok){
      if(!ok)throw new Error('That is not the team passcode.');
      var iv=crypto.getRandomValues(new Uint8Array(12));
      return aes(raw,'encrypt').then(function(k){
        return crypto.subtle.encrypt({name:'AES-GCM',iv:iv},k,te.encode(secret));
      }).then(function(ct){return {iv:b64(iv),ct:b64(ct)};});
    });
  });
}
function gate(){
  return new Promise(function(done){
    var g=document.createElement('div');g.id='teamGate';
    g.innerHTML='<form id="teamGateForm"><div class="tg-t">SkyMorph documents</div>'
      +'<div class="tg-s">Enter the team passcode to continue.</div>'
      +'<input id="teamPass" type="password" inputmode="numeric" autocomplete="off" placeholder="Passcode">'
      +'<button type="submit">Unlock</button><div class="tg-m" id="teamGateMsg"></div>'
      +'<div class="tg-f">SkyMorph - A unit of Aviyat World</div></form>';
    document.body.appendChild(g);
    var inp=el('teamPass'),msg=el('teamGateMsg');
    inp.focus();
    el('teamGateForm').addEventListener('submit',function(e){
      e.preventDefault();
      var v=inp.value.trim();if(!v)return;
      msg.textContent='Checking…';
      derive(v).then(function(raw){
        return check(raw).then(function(ok){
          if(!ok){msg.textContent='Wrong passcode. Try again.';inp.select();return;}
          try{localStorage.setItem(LS,b64(raw));}catch(e2){}
          g.remove();done(raw);
        });
      }).catch(function(){msg.textContent='This browser cannot check the passcode.';});
    });
  });
}
function unlock(){
  if(!window.crypto||!crypto.subtle){
    document.body.insertAdjacentHTML('beforeend','<div id="teamGate"><form><div class="tg-t">SkyMorph documents</div><div class="tg-s">This page must be opened over https.</div></form></div>');
    return new Promise(function(){});
  }
  var saved=null;
  try{saved=localStorage.getItem(LS);}catch(e){}
  var p=saved?check(unb64(saved)).then(function(ok){return ok?unb64(saved):gate();},gate):gate();
  return p.then(function(raw){
    return openToken(raw).catch(function(){return null;}).then(function(t){
      token=t;
      document.documentElement.classList.remove('locked');
      return raw;
    });
  });
}
function lock(){try{localStorage.removeItem(LS);}catch(e){}location.reload();}

/* ---------- GitHub as the shared store ---------- */
function api(path,method,body,raw){
  var c=cfg();
  return fetch('https://api.github.com/repos/'+c.owner+'/'+c.repo+'/contents/'+path.split('/').map(encodeURIComponent).join('/'),{
    method:method||'GET',cache:'no-store',
    headers:{'Authorization':'Bearer '+token,'Accept':raw?'application/vnd.github.raw+json':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},
    body:body?JSON.stringify(body):undefined
  });
}
function getJSON(path){
  return api(path).then(function(r){
    if(r.status===404)return {data:null,sha:null};
    if(!r.ok)throw new Error('GitHub '+r.status);
    return r.json().then(function(j){
      var data=null;
      try{data=j.content?JSON.parse(td.decode(unb64(j.content))):null;}catch(e){}
      return {data:data,sha:j.sha};
    });
  });
}
function putJSON(path,data,sha,msg){
  var body={message:msg,content:b64(te.encode(JSON.stringify(data,null,1)))};
  if(sha)body.sha=sha;
  return api(path,'PUT',body);
}
/* read, change, write back; if someone else wrote in between, start again */
function update(path,mutate,msg){
  var tries=0;
  function go(){
    return getJSON(path).then(function(cur){
      var next=mutate(cur.data||{});
      return putJSON(path,next,cur.sha,msg).then(function(r){
        if(r.ok)return next;
        if((r.status===409||r.status===422)&&++tries<8)return wait(150+Math.random()*350).then(go);
        throw new Error('GitHub '+r.status);
      });
    });
  }
  return go();
}

/* ---------- serial numbers ---------- */
function fy(d){var y=d.getFullYear(),s=(d.getMonth()>=3)?y:y-1;return s+'-'+String(s+1).substring(2);}
function pad(n,w){n=String(n);while(n.length<w)n='0'+n;return n;}
function bump(last){
  var m=String(last).match(/^(.*?)(\d+)(\D*)$/);
  if(!m)return last+'-1';
  var pre=m[1],n=m[2],suf=m[3],cur=fy(new Date()),f=pre.match(/(\d{4}-\d{2})(?!\d)/);
  /* new financial year: carry the format over and start again from 1 */
  if(f&&f[1]!==cur)return pre.replace(f[1],cur)+pad(1,n.length)+suf;
  return pre+pad(+n+1,n.length)+suf;
}
function claim(){
  var out='';
  return update('serials.json',function(d){
    var last=(d[TYPE]&&d[TYPE].last)||DEF[TYPE].replace('{FY}',fy(new Date()));
    out=bump(last);
    d[TYPE]={last:out,at:new Date().toISOString()};
    return d;
  },'Take '+TYPE+' number').then(function(){return out;});
}
function setLast(v){
  return update('serials.json',function(d){
    d[TYPE]={last:v,at:new Date().toISOString()};return d;
  },'Set last '+TYPE+' number to '+v);
}
function noEl(){return el('f_no');}
function setNo(n){
  var e=noEl();if(!e)return;
  e.value=n;known=n;
  e.dispatchEvent(new Event('input',{bubbles:true}));
}
function claimInto(){
  if(!token)return;
  say('Getting the next number…');
  claim().then(function(n){setNo(n);say('Number '+n+' taken','ok');})
    .catch(function(){say('Could not reach the team store — number not synced','bad');});
}

/* ---------- team documents ---------- */
function saveDoc(){
  if(!token)return Promise.resolve(false);
  var no=(noEl()&&noEl().value||'').trim();
  if(!no){say('Not saved to team — no number','bad');return Promise.resolve(false);}
  var key=safe(no),dir='docs/'+TYPE+'/',path=dir+key+'.json';
  var custEl=el('b_name')||el('f_cust'),cust=custEl?custEl.value.trim():'';
  var meta={no:no,cust:cust,date:(el('f_date')||{}).value||'',total:(el('liveTotal')||{}).textContent||'',at:new Date().toISOString()};
  var doc=window.snap();
  say('Saving to team…');
  return getJSON(dir+'index.json').then(function(ix){
    var had=ix.data&&ix.data[key];
    if(had&&had.cust&&cust&&had.cust!==cust&&
       !confirm('A team document numbered '+no+' already exists for "'+had.cust+'".\n\nReplace it with this one for "'+cust+'"?')){
      say('Not saved to team — number already used','bad');return false;
    }
    function put(n){
      return api(path).then(function(r){return r.status===404?null:r.json().then(function(j){return j.sha;});}).then(function(sha){
        return putJSON(path,doc,sha,'Save '+TYPE+' '+no).then(function(r){
          if(r.ok)return true;
          if((r.status===409||r.status===422)&&n<3)return wait(300).then(function(){return put(n+1);});
          throw new Error('GitHub '+r.status);
        });
      });
    }
    return put(0).then(function(){
      return update(dir+'index.json',function(d){d[key]=meta;return d;},'Index '+TYPE+' '+no);
    }).then(function(){say('Saved to team','ok');return true;});
  }).catch(function(){say('Could not save to team — keep your own copy','bad');return false;});
}
function openList(){
  if(!token){alert('Team sync is not set up on this site yet.');return;}
  var m=document.createElement('div');m.id='teamModal';m.className='noprint';
  var opts=CAN_OPEN[TYPE].map(function(t){return '<option value="'+t+'">'+NAMES[t]+'</option>';}).join('');
  m.innerHTML='<div class="tm-box"><div class="tm-h"><b>Team documents</b>'
    +'<select id="tmType">'+opts+'</select>'
    +'<input id="tmQ" placeholder="Search number or customer"><button id="tmX" type="button">Close</button></div>'
    +'<div class="tm-l" id="tmList">Loading…</div></div>';
  document.body.appendChild(m);
  var items=[],kind=TYPE;
  function close(){m.remove();}
  function draw(){
    var q=el('tmQ').value.trim().toLowerCase(),h='';
    items.forEach(function(it){
      if(q&&(it.no+' '+it.cust).toLowerCase().indexOf(q)<0)return;
      h+='<button type="button" class="tm-r" data-k="'+esc(it.key)+'"><span class="a">'+esc(it.no)+'</span>'
        +'<span class="b">'+esc(it.cust||'—')+'</span><span class="c">'+esc(it.date)+'</span><span class="d">'+esc(it.total)+'</span></button>';
    });
    el('tmList').innerHTML=h||'<div class="tm-e">Nothing saved here yet.</div>';
  }
  function load(){
    el('tmList').textContent='Loading…';
    getJSON('docs/'+kind+'/index.json').then(function(ix){
      var d=ix.data||{};
      items=Object.keys(d).map(function(k){var o=d[k];return {key:k,no:o.no||k,cust:o.cust||'',date:o.date||'',total:o.total||'',at:o.at||''};});
      items.sort(function(a,b){return a.at<b.at?1:-1;});
      draw();
    }).catch(function(){el('tmList').innerHTML='<div class="tm-e">Could not reach the team store.</div>';});
  }
  el('tmX').onclick=close;
  m.addEventListener('click',function(e){if(e.target===m)close();});
  el('tmQ').addEventListener('input',draw);
  el('tmType').addEventListener('change',function(){kind=this.value;load();});
  el('tmList').addEventListener('click',function(e){
    var b=e.target.closest('.tm-r');if(!b)return;
    if(!confirm('Open this document? What is on the sheet now will be replaced.'))return;
    api('docs/'+kind+'/'+b.getAttribute('data-k')+'.json','GET',null,true).then(function(r){
      if(!r.ok)throw new Error('GitHub '+r.status);
      return r.json();
    }).then(function(o){
      window.restore(o);
      known=noEl()?noEl().value:'';
      close();say('Opened from team','ok');
    }).catch(function(){alert('That document could not be opened.');});
  });
  load();
}

/* ---------- toolbar ---------- */
function say(t,cls){if(chip){chip.textContent=t;chip.className='team-chip'+(cls?' '+cls:'');}}
function wireTool(){
  var bar=document.querySelector('.bar');if(!bar||!TYPE)return;
  var live=bar.querySelector('.live');
  var home=document.createElement('a');home.className='btn';home.href='./';home.textContent='← All documents';
  var docs=document.createElement('button');docs.className='btn';docs.type='button';docs.textContent='Team documents';docs.onclick=openList;
  chip=document.createElement('span');
  bar.insertBefore(home,bar.firstChild);
  bar.insertBefore(docs,live);bar.insertBefore(chip,live);
  say(token?'Team sync on':'Team sync not set up — working on this computer only',token?'ok':'bad');
  known=noEl()?noEl().value:'';

  /* "New ..." takes the next shared number */
  var origNew=window[NEWFN];
  if(origNew)window[NEWFN]=function(){if(origNew()===true)claimInto();};
  /* printing and "Save file" also keep a team copy */
  var origPrint=window.doPrint;
  if(origPrint)window.doPrint=function(){
    if(!token){origPrint();return;}
    var fired=false,go=function(){if(!fired){fired=true;origPrint();}};
    saveDoc().then(go,go);setTimeout(go,8000);
  };
  var origExport=window.exportJSON;
  if(origExport)window.exportJSON=function(){origExport();saveDoc();};
  /* typing a different number: the team count can follow it */
  var e=noEl();
  if(e)e.addEventListener('change',function(){
    var v=e.value.trim();
    if(!token||!v||v===known)return;
    known=v;
    if(confirm('Make "'+v+'" the team\'s last '+TYPE+' number?\n\nOK: the next new document continues from it.\nCancel: use it for this document only.')){
      setLast(v).then(function(){say('Team number set to '+v,'ok');})
        .catch(function(){say('Could not reach the team store — number not synced','bad');});
    }
  });
  /* first time on this computer: start with a real number */
  if(window.__fresh)claimInto();
}

/* ---------- styles ---------- */
var css=document.createElement('style');
css.textContent='#teamGate{position:fixed;inset:0;z-index:999;background:#16293c;display:flex;align-items:center;justify-content:center;padding:16px;font-family:Arial,Helvetica,sans-serif}'
+'#teamGate form{background:#fff;border-radius:10px;padding:26px 24px;width:320px;max-width:100%;text-align:center;box-shadow:0 18px 50px rgba(0,0,0,.35)}'
+'#teamGate .tg-t{font-size:20px;font-weight:bold;color:#1f3a5f}'
+'#teamGate .tg-s{font-size:13px;color:#5f6d78;margin:6px 0 16px}'
+'#teamGate input{width:100%;font-size:18px;padding:10px;border:1px solid #cfd8df;border-radius:6px;text-align:center;letter-spacing:.2em;background:#fff;color:#243746}'
+'#teamGate input:focus{outline:2px solid #2f8f6d;border-color:transparent}'
+'#teamGate button{width:100%;margin-top:10px;padding:10px;border:0;border-radius:6px;background:#2f8f6d;color:#fff;font-size:15px;font-weight:bold;cursor:pointer}'
+'#teamGate .tg-m{min-height:18px;margin-top:10px;font-size:12.5px;color:#a4442f}'
+'#teamGate .tg-f{margin-top:8px;font-size:10px;color:#8a949c}'
+'.team-chip{font-size:11.5px;color:#b9ccd9;white-space:nowrap}.team-chip.ok{color:#87c9ac}.team-chip.bad{color:#f1b3a5}'
+'a.btn{text-decoration:none;display:inline-block}'
+'#teamModal{position:fixed;inset:0;z-index:900;background:rgba(12,26,40,.55);display:flex;align-items:flex-start;justify-content:center;padding:6vh 14px;font-family:Arial,Helvetica,sans-serif;font-size:13px}'
+'#teamModal .tm-box{background:#fff;border-radius:8px;width:760px;max-width:100%;max-height:84vh;display:flex;flex-direction:column;box-shadow:0 18px 50px rgba(0,0,0,.35)}'
+'#teamModal .tm-h{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 14px;border-bottom:1px solid #dde3e8;color:#1f3a5f}'
+'#teamModal .tm-h b{font-size:15px;margin-right:auto}'
+'#teamModal select,#teamModal .tm-h input,#teamModal .tm-h button{font:inherit;padding:6px 8px;border:1px solid #cfd8df;border-radius:5px;background:#fff;color:#243746}'
+'#teamModal .tm-h input{flex:1;min-width:150px}#teamModal .tm-h button{cursor:pointer}'
+'#teamModal .tm-l{overflow:auto;padding:6px 8px 10px}'
+'#teamModal .tm-r{display:flex;gap:10px;width:100%;text-align:left;padding:8px;border:0;border-bottom:1px solid #eef2f5;background:#fff;cursor:pointer;font:inherit;color:#243746}'
+'#teamModal .tm-r:hover{background:#f2f8fd}'
+'#teamModal .tm-r .a{width:170px;font-weight:bold;flex:none}#teamModal .tm-r .b{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
+'#teamModal .tm-r .c{width:110px;color:#6b7883;flex:none}#teamModal .tm-r .d{width:110px;text-align:right;flex:none}'
+'#teamModal .tm-e{padding:18px;color:#6b7883;text-align:center}'
+'@media (max-width:600px){#teamModal .tm-r .c{display:none}#teamModal .tm-r .a{width:120px}}'
+'@media print{#teamGate,#teamModal{display:none !important}}';
document.head.appendChild(css);

var ready=unlock().then(function(raw){wireTool();return raw;});
window.Team={ready:ready,seal:seal,lock:lock,hasSync:function(){return !!token;},unlock:unlock,_bump:bump};
})();
