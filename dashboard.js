// the buttons send exactly these minutes; the server computes each (1y = 365 days)
const RANGES=[["15m",15],["1h",60],["6h",360],["24h",1440],["7d",10080],["30d",43200],["90d",129600],["1y",525600]];
let minutes=60, latChart, lossChart, trafficChart, trafficUpChart, usageDaysChart, qMosChart, qDnsChart, editing=false, selected=null, last=null;
// ---------------------------------------------------------------- tabs and the address
// One tab per question. The address holds the view - #/<tab>?range=<label> - so a view can be
// linked or bookmarked and Back steps through views. Each tab fetches only what it shows.
const TABS=[["overview","Overview"],["network","Network"],["devices","Devices"],["history","History"],
            ["usage","Usage"],["system","System"]];
// every endpoint the page calls, by tab; "status" (header, banner) and "live" are on every tab
const TAB_FETCH={overview:["kpi","overview","digest"], network:["kpi","summary","usage","devices","mesh","wifi"],
                 devices:["summary","usage","devices","mesh"], history:["summary","series","incidents","events","quality"],
                 usage:["usage","speedtest"], system:["host","dns","settings","setup","security"]};
let tab="overview";
// which devices the traffic charts show: kept here (the panel is redrawn every refresh) and in
// the browser, by device id, so a rename doesn't reset it. "only" shows one device, whoever
// else joins the busiest list later; otherwise everything except what you've unticked.
// Device ids always start with "dev:" (config.device_target), so "other" (Everything else) can't collide with one.
const TRAFFIC_HIDDEN_MAX=100, trafficKey=d=>d.id??"other";
let trafficHidden=new Set(), trafficOnly=null;
try{ trafficHidden=new Set(JSON.parse(localStorage.getItem("hearth_traffic_hidden")||"[]")); trafficOnly=localStorage.getItem("hearth_traffic_only")||null }catch(e){}
try{ minutes=+localStorage.getItem("hearth_minutes")||60 }catch(e){}
if(!RANGES.some(r=>r[1]===minutes)) minutes=60;  // a stored value from an older page
// colours come from the page's tokens (dashboard.html), so both themes draw from one source.
// COLORS: the series palette (no status colour); CC: chart text, grid and named series colours
const tok=n=>getComputedStyle(document.documentElement).getPropertyValue("--"+n).trim();
let COLORS=[], OTHER="", CC={};
function readTheme(){
  COLORS=["s1","s2","s3","s4","s5","s6"].map(tok); OTHER=tok("s-other");
  CC={text:tok("text"),muted:tok("muted"),grid:tok("line"),blue:tok("s1"),purple:tok("s2"),teal:tok("s3"),orange:tok("s4")};
}
readTheme();
// the header's toggle: a choice is remembered and wins over the system's preference; with no
// choice made, the page follows the system as it changes
function themeButton(){
  const light=document.documentElement.dataset.theme==="light", b=$("#theme");
  b.textContent=light?"Dark":"Light"; b.setAttribute("aria-label",`Switch to the ${light?"dark":"light"} theme`);
}
function applyTheme(t,remember){
  document.documentElement.dataset.theme=t; if(remember) save("hearth_theme",t);
  readTheme(); themeButton(); refresh().then(()=>resizeCharts()).catch(()=>{});   // charts take colours when drawn
}
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtT=ts=>{const d=new Date(ts*1000);return minutes>1440?d.toLocaleString([], {weekday:"short",hour:"2-digit",minute:"2-digit"}):d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:minutes<=60?"2-digit":undefined})};
const ago=ts=>{if(!ts)return"–";const s=Date.now()/1000-ts;return s<90?`${s|0}s ago`:s<5400?`${s/60|0}m ago`:s<172800?`${s/3600|0}h ago`:`${s/86400|0}d ago`};
const ms=v=>v==null?"–":(v<10?v.toFixed(1):Math.round(v))+" ms";
const pc=v=>v==null?"–":v+"%";
const fmtB=b=>b==null?"–":b>=1e9?(b/1e9).toFixed(2)+" GB":b>=1e6?(b/1e6).toFixed(b>=1e8?0:1)+" MB":b>=1e3?Math.round(b/1e3)+" KB":b+" B";
const mbps=v=>v==null?"–":(v<0.05?"0":v<10?v.toFixed(1):Math.round(v))+" Mb/s";
const fmtSpan=s=>{const d=s/86400|0,h=s%86400/3600|0,m=s%3600/60|0;return d?`${d} d ${h} h`:h?`${h} h ${m} m`:`${m} m`};
const every=()=>minutes<=60?5000:minutes<=360?15000:60000;  // long windows change slowly and cost more
const rangeLabel=()=>RANGES.find(r=>r[1]==minutes)?.[0]||minutes+"m";
const save=(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}};

function buildRanges(){
  $("#ranges").innerHTML=RANGES.map(([l,m])=>`<button data-m="${m}" class="${m==minutes?"on":""}" aria-pressed="${m==minutes}">${l}</button>`).join("");
  $("#ranges").querySelectorAll("button").forEach(b=>b.onclick=()=>go({range:RANGES.find(r=>r[1]==b.dataset.m)[0]}));
}

// the view in the address: values are checked against the known tabs and ranges, anything else
// falls back (a stale or hand-edited link still opens something sensible)
function readHash(){
  const h=location.hash.replace(/^#\/?/,""), [name,query]=[h.split("?")[0],h.split("?").slice(1).join("?")];
  const q=new URLSearchParams(query), at=q.get("at"), it=q.get("item");
  return {tab:TABS.some(t=>t[0]===name)?name:"overview",
          range:RANGES.find(r=>r[0]===q.get("range"))?.[0]||null,
          // a moment to show (History): whole seconds only; checked against the server's clock
          // when shown (atShown); never sent anywhere
          at:/^\d{9,11}$/.test(at||"")?+at:null,
          // what the side panel shows: a known kind, matched against loaded data before it's shown
          item:validItem(it)?it:null};
}
function hashFor(t,range,at,item){
  const q={range}; if(at) q.at=at; if(item) q.item=item;
  return `#/${t}?${new URLSearchParams(q)}`;
}
// side panel items: a device (dev:), a mesh unit (unit:, the map's mesh: key), the router, the
// internet, an area or a named group of the map
// an episode (ep:<its start, whole seconds>) or a data source (src:<name>)
const ITEM_RE=/^(dev:.+|unit:.+|router|internet|self|area:.+|grp:.+|ep:\d{9,11}|src:[a-z][a-z0-9_]{0,31}|alerts)$/, ITEM_MAX=128;
const itemKind=it=>it==="alerts"?"alerts":it?.startsWith("ep:")?"ep":it?.startsWith("src:")?"src":"map";
const validItem=it=>typeof it==="string"&&it.length<=ITEM_MAX&&ITEM_RE.test(it);   // the one check, for the address and the server's items
const itemKey=it=>it?.startsWith("unit:")?"mesh:"+it.slice(5):it;
const keyItem=k=>k?.startsWith("mesh:")?"unit:"+k.slice(5):k;
let at=null, lastStatus=null, item=null;
// panelOpener: what had focus when the panel opened (focus returns there); panelNote: a message
// shown in place of an item that couldn't be shown (not found, or its data failed to load)
let panelOpener=null, panelNote=null;
// an at= link names a moment in the last 400 days by the server's clock (not this device's);
// until the first status arrives it stays pending
const AT_KEEP_S=400*86400;
const atShown=()=>at!=null&&lastStatus?.updated!=null&&at>=lastStatus.updated-AT_KEEP_S&&at<=lastStatus.updated+900?at:null;
// show the view the address asks for: tab, range (the last one used if the link has none)
function applyHash(){
  const v=readHash();
  if(v.range){ minutes=RANGES.find(r=>r[0]===v.range)[1]; save("hearth_minutes",minutes) }
  tab=v.tab; at=v.at; atScrolled=false;
  // focus returns here on close: what the click handlers recorded, else what had focus (a link
  // typed or pasted into the address has neither, so nothing is refocused)
  if(v.item&&v.item!==item&&!panelOpener) panelOpener=document.activeElement;
  if(!v.item) panelOpener=null;
  item=v.item; selected=itemKey(item); panelNote=null;
  document.querySelectorAll(".tabpanel").forEach(p=>p.hidden=p.id!=="tab-"+tab);
  document.querySelectorAll("#tabs [role=tab]").forEach(b=>{ const on=b.dataset.tab===tab;
    b.setAttribute("aria-selected",on); b.tabIndex=on?0:-1;
    if(on) b.scrollIntoView({block:"nearest",inline:"nearest"}) });  // a narrow screen scrolls the bar to it
  buildRanges();
}
// change the view: a new entry in the history (Back returns to the previous view)
// the side panel stays open across a range change on the same tab, and closes on a tab change
function go({tab:t=tab,range=rangeLabel(),at:moment=null,item:it=(t===tab?item:null)}={}){
  const h=hashFor(t,range,moment,it);
  if(h!==location.hash) history.pushState(null,"",h);
  applyHash(); refresh().then(()=>resizeCharts()).catch(()=>{});
}
let atScrolled=false;   // the moment from at= is scrolled to once, not on every refresh
// a chart drawn while its tab was hidden has no size: fit them once their tab shows
function resizeCharts(){ [latChart,lossChart,trafficChart,trafficUpChart,usageDaysChart,qMosChart,qDnsChart].forEach(c=>c?.resize()) }
function buildTabs(){
  $("#tabs").innerHTML=TABS.map(([k,l])=>`<button role="tab" id="tabbtn-${k}" data-tab="${k}" aria-controls="tab-${k}">${l}</button>`).join("");
  $("#tabs").querySelectorAll("[role=tab]").forEach(b=>b.onclick=()=>go({tab:b.dataset.tab}));
  // the WAI-ARIA tabs pattern: arrows move between tabs, Home/End jump to the ends
  $("#tabs").addEventListener("keydown",e=>{
    const keys=TABS.map(t=>t[0]), i=keys.indexOf(tab);
    const j={ArrowRight:i+1,ArrowLeft:i-1,Home:0,End:keys.length-1}[e.key];
    if(j==null) return;
    e.preventDefault();
    const t=keys[(j+keys.length)%keys.length];
    go({tab:t}); $("#tabbtn-"+t).focus();
  });
}
// Back/Forward, and links that change the address (tiles, "Needs attention"): show that view.
// hashchange covers both (pushState itself fires neither, so go() isn't drawn twice)
window.addEventListener("hashchange",()=>{ applyHash(); refresh().then(()=>resizeCharts()).catch(()=>{}) });
const get=p=>fetch(p+(p.includes("?")?"&":"?")+"minutes="+minutes).then(r=>{if(!r.ok)throw new Error(p);return r.json()});
// the server decides every level (hearth/levels.py); the page only picks a colour for it
const LV={ok:"good",warn:"warn",bad:"bad",unknown:"nodata"};
// the word for each, said with the shape (the .dot/.tag ::before words in dashboard.html match)
const LV_WORD={[LV.ok]:"good",[LV.warn]:"fair",[LV.bad]:"poor",[LV.unknown]:"no data"};
const lvl=x=>LV[x?.level]??LV.unknown;
const ORDER=[LV.unknown,LV.ok,LV.warn,LV.bad];  // least to most severe, for picking a group's worst colour
// one record per device id: several rows can share an id (a MAC seen at an old address too);
// the online, most recently seen one wins - the same rule as the server's device_names
const devInfo=dev=>{ const out={}; for(const d of dev){ const o=out[d.id];
  if(!o||(d.online|0)>(o.online|0)||((d.online|0)===(o.online|0)&&(d.last_seen||0)>(o.last_seen||0))) out[d.id]=d }
  return out };
const renameBtn=(key,name)=>`<button class="rename" title="Rename" aria-label="Rename ${esc(name)}" data-key="${esc(key)}" data-name="${esc(name)}">✎</button>`;

// ---------------------------------------------------------------- the map
const BAND={band2_4:"2.4 GHz",band5:"5 GHz",band6:"6 GHz"};
// the mesh's own guess at a device's type, as a small icon
const KIND={phone:"📱",tablet:"📱",pc:"🖥️",laptop:"💻",computer:"🖥️",tv:"📺",camera:"📷",speaker:"🔊",watch:"⌚",printer:"🖨️",
            game:"🎮",console:"🎮",iot:"💡",smart_home:"💡",iot_device:"💡"};
// own properties only: a type the mesh calls "constructor" mustn't find Object's (#126 review)
const kindIcon=k=>k&&ownProp(KIND,k)?KIND[k]+" ":"";
// the mesh's type words, where its own read badly (#122: Deco says "iot_device")
const KIND_WORD_OF={iot_device:"smart home device",smart_home:"smart home device",iot:"smart home device"};
// which of the mesh's networks a device is on; the main one isn't worth a mark on the map
const NETWORK_WORD={main:"main",guest:"guest network",iot:"IoT network"};
// a satellite's backhaul at a glance: its best band's signal and speed
function bestBand(n){
  const r=n.rssi||{}; const b=Object.keys(r).sort((x,y)=>r[y]-r[x])[0];
  return b?{band:b,rssi:r[b],grade:n.grades?.[b],rx:n.rate_rx?.[b]}:null;
}
const rate=v=>v==null?"–":v>=1000?(v/1000).toFixed(1)+" Gb/s":v+" Mb/s";
const bars=v=>v==null?"":"●".repeat(Math.max(0,Math.min(3,v)))+"○".repeat(Math.max(0,3-Math.min(3,v)));
function uplinkText(n){
  if(n.role==="main") return "main unit · wired to the router";
  if(n.backhaul==="wired") return "wired to "+(n.parentName||"the main unit");
  const sig=(n.bands||[]).map(b=>`${BAND[b]||b} ${bars(n.signal?.[b])}`).join(" · ");
  return `wireless to ${n.parentName||"the main unit"}${sig?" · "+sig:""}`;
}

// the real layout, read from the mesh system: router -> main node -> satellites -> devices
function buildMeshTree(sum,use,dev,m){
  const stat=Object.fromEntries(sum.devices.map(d=>[d.id,d]));
  const nowBy=Object.fromEntries((use.current?.devices||[]).map(d=>[d.id,d]));
  const usedBy=Object.fromEntries((use.window?.devices||[]).map(d=>[d.id,d]));
  const info=devInfo(dev);
  const idByIp=Object.fromEntries(dev.filter(d=>d.ip).map(d=>[d.ip,d.id]));
  // match the mesh's device to Hearth's record: the address the mesh sees now wins (a device
  // that changed DHCP address may be keyed by IP in Hearth), then the MAC
  const pick=(id,ip)=>(ip&&idByIp[ip])||id;
  // unitOf / linkOf feed the Devices filters: the mesh unit a device hangs off, and wifi or wired
  const placed=new Set(), areaOf={}, unitOf={}, linkOf={};
  const node={}; for(const n of m.nodes) node[n.mac]={...n};
  for(const n of Object.values(node)) n.parentName=node[n.parent]?.name;
  const devNode=(d,area)=>{
    const id=pick(d.id,d.ip); placed.add(id); placed.add(d.id); areaOf[id]=area+" · "+(d.link==="wired"?"wired":BAND[d.link]||d.link);
    unitOf[id]=area; linkOf[id]=d.link==="wired"?"wired":String(d.link||"").startsWith("band")?"wifi":undefined;
    const s=stat[id], n=nowBy[id]||nowBy[d.id], self=d.id===m.self;
    // the server's level: wireless devices against their mesh unit, wired ones by their own pings
    const hl=self?"self":lvl(d.level?d:s);
    return {key:id,kind:"device",id,ip:d.ip,mac:d.mac,devkind:d.kind,network:d.network,quality:d.quality,qualityWhy:d.quality_why,
            name:kindIcon(d.kind)+(s?.name||info[id]?.name||d.name)+(self?" · Hearth":""),self,link:d.link,
            edge:d.link==="wired"?"wired":"wireless",health:hl,
            mbps:n?n.down_mbps+n.up_mbps:0,stat:s,now:n,used:usedBy[id]||usedBy[d.id],info:info[id]};
  };
  // devices the mesh doesn't list, placed by the server from their reply times (/api/mesh unlisted)
  const unlisted=Object.fromEntries((m.unlisted||[]).map(u=>[u.id,u])), byUnit={};
  // what the mesh already draws (its devices, its units) is never drawn again; one entry per id
  const drawn=new Set([...m.devices.map(d=>pick(d.id,d.ip)),...m.devices.map(d=>d.id),
                       ...m.nodes.map(n=>pick("dev:"+n.mac,n.ip))]), queued=new Set();
  for(const u of Object.values(unlisted))
    if(u.placement==="timing"&&u.node&&!drawn.has(u.id)&&!queued.has(u.id)){ queued.add(u.id); (byUnit[u.node]||=[]).push(u) }
  const looseNode=(id,area,why,unit)=>{ placed.add(id); areaOf[id]=area; if(unit) unitOf[id]=unit; const s=stat[id],n=nowBy[id];
    return {key:id,kind:"device",id,name:s?.name||info[id]?.name||unlisted[id]?.name||usedBy[id]?.name||n?.name||info[id]?.ip||id.replace(/^dev:(ip:)?/,""),
            edge:"loose",health:lvl(s),placementWhy:why,mbps:n?n.down_mbps+n.up_mbps:0,stat:s,now:n,used:usedBy[id],info:info[id]} };
  const visited=new Set();  // a malformed reply could make two nodes each other's parent
  const decoNode=n=>{
    visited.add(n.mac);
    const id=pick("dev:"+n.mac,n.ip); placed.add(id);
    const kids=Object.values(node).filter(c=>c.parent===n.mac&&!visited.has(c.mac)).map(decoNode);
    const devs=m.devices.filter(d=>d.node===n.mac).map(d=>devNode(d,n.name||n.mac));
    // placed here by timing: a dotted line, "probably" in the detail
    const probably=(byUnit[n.mac]||[]).map(u=>looseNode(u.id,(n.name||n.mac)+" · probably",u.why,n.name||n.mac));
    // the server's level: offline, a satellite's backhaul signal, or the main unit's own pings
    const hl=lvl(n);
    return {key:"mesh:"+n.mac,kind:"deco",id,name:n.name||n.mac,node:n,edge:n.role==="main"||n.backhaul==="wired"?"wired":"wireless",
            health:hl,stat:stat[id],info:info[id],children:[...kids,...devs,...probably]};
  };
  const core=sum.core||{}, gw=core.gateway;
  const inets=Object.entries(core).filter(([k,v])=>k.startsWith("inet:")&&v.p50!=null).map(([,v])=>v).sort((a,b)=>a.p50-b.p50);
  const router={key:"router",kind:"router",name:"Router",health:lvl(gw),stat:gw,
                children:Object.values(node).filter(n=>n.role==="main").map(decoNode)};
  // every device node on the mesh, to tidy names and attach extra addresses
  const meshDevs=[]; const collect=n=>{ if(n.kind==="device"&&n.edge!=="loose") meshDevs.push(n); (n.children||[]).forEach(collect) };
  router.children.forEach(collect);
  // one machine with two connections (e.g. a Mac on cable and WiFi) shows as two entries with
  // the same name: tell them apart by how they connect, not by address
  const base=n=>n.ip?n.name.replace(" · "+n.ip,""):n.name, seen={};
  meshDevs.forEach(n=>{ seen[base(n)]=(seen[base(n)]||0)+1 });
  meshDevs.forEach(n=>{ if(seen[base(n)]>1&&!n.self) n.name=`${base(n)} (${n.link==="wired"?"wired":BAND[n.link]||n.link})` });
  // a second address on the same network card (same MAC) belongs to that device, not elsewhere
  const byMac=Object.fromEntries(meshDevs.filter(n=>n.mac).map(n=>[n.mac,n]));
  // only devices that are around now (online, or using the internet now): old addresses and
  // devices gone for hours would just clutter the map - they're still in the devices table
  const loose=[...new Set([...sum.devices.map(d=>d.id),...Object.keys(nowBy),...Object.keys(unlisted)])]
    // asleep devices (a sleeping card answering ARP) aren't around to place: the Devices tab lists them (#122)
    .filter(id=>!placed.has(id)&&((info[id]?.online&&info[id]?.state!=="asleep")||nowBy[id]||unlisted[id]))
    .filter(id=>{ const owner=byMac[info[id]?.mac]; if(!owner) return true;
      (owner.alsoAt||=[]).push(info[id].ip); placed.add(id); areaOf[id]=areaOf[owner.id]; unitOf[id]=unitOf[owner.id]; linkOf[id]=linkOf[owner.id]; return false });
  const LOOSE="Location unknown";
  if(loose.length) router.children.push({key:"area:loose",kind:"area",role:"loose",edge:"loose",name:LOOSE,health:LV.unknown,
    note:"Hearth sees these on the network, but the mesh doesn't list them and their reply times don't clearly point to one "+
         "unit (or they don't answer pings). Their line is dotted because the route is unknown.",
    // a timing match whose unit isn't on the map can't go under it: say so, not "replies like X"
    children:loose.map(id=>looseNode(id,LOOSE,unlisted[id]?.placement==="timing"
      ?"its replies point to a unit that isn't on the map right now":unlisted[id]?.why))});
  const line=[core.isp,inets[0]].filter(Boolean);
  const worst=line.map(lvl).sort((a,b)=>ORDER.indexOf(b)-ORDER.indexOf(a))[0]??LV.unknown;
  const root={key:"internet",kind:"internet",name:"Internet",health:worst,stat:inets[0],isp:core.isp,children:[router]};
  const sumUp=n=>{ if(n.children){ const s=n.children.reduce((a,c)=>a+sumUp(c),0); if(n.kind!=="device") n.mbps=s } return n.mbps||0 };
  sumUp(root);
  if(use.current) router.mbps=root.mbps=use.current.down_mbps+use.current.up_mbps;
  return {root,areaOf,unitOf,linkOf,fromMesh:true};
}

// the layout inferred from timing (when the mesh system can't be read)
function buildTree(sum,use,dev){
  const stat=Object.fromEntries(sum.devices.map(d=>[d.id,d]));
  const nowBy=Object.fromEntries((use.current?.devices||[]).map(d=>[d.id,d]));
  const usedBy=Object.fromEntries((use.window?.devices||[]).map(d=>[d.id,d]));
  const info=devInfo(dev);
  const placed=new Set(), areaOf={};
  const devNode=(id,area)=>{
    placed.add(id); areaOf[id]=area;
    const s=stat[id], n=nowBy[id];
    return {key:id,kind:"device",id,name:s?.name||info[id]?.name||usedBy[id]?.name||n?.name||id,
            health:lvl(s),mbps:n?n.down_mbps+n.up_mbps:0,stat:s,now:n,used:usedBy[id],info:info[id]};
  };
  const area=(h,kind)=>{const n={key:h.group!=null?"grp:"+h.group:"area:"+h.name,kind:"area",role:kind,group:h.group,
      name:h.short||h.name,title:h.name,health:lvl(h),stat:h};
    n.children=h.targets.filter(t=>t.startsWith("dev:")).map(t=>devNode(t,h.name)); return n};
  const hop=p=>sum.hops.find(h=>h.pos===p);
  const local=hop("local");
  let inner=local?area(local,"local"):{key:"area:local",kind:"area",role:"local",name:"This computer's segment",health:LV.unknown,children:[]};
  const selfName=use.self_id?(usedBy[use.self_id]?.name||nowBy[use.self_id]?.name):null;
  inner.children.unshift({...(use.self_id?devNode(use.self_id,inner.name):{key:"self",kind:"device",health:LV.unknown,mbps:0}),
                          self:true,name:(selfName||"This computer")+" · Hearth",health:"self"});  // not pinged: its own colour, no health claim
  for(const r of sum.hops.filter(h=>h.pos==="relay")){ const a=area(r,"relay"); a.children.push(inner); inner=a }
  // the router and the internet are measured directly: use their own stats (with a median)
  const core=sum.core||{}, gw=core.gateway;
  const inets=Object.entries(core).filter(([k,v])=>k.startsWith("inet:")&&v.p50!=null).map(([,v])=>v).sort((a,b)=>a.p50-b.p50);
  const router={key:"router",kind:"router",name:"Router",health:lvl(gw),stat:gw,children:[inner]};
  for(const b of sum.branches) router.children.push(area(b,"branch"));
  // devices with traffic or a known state that the layout hasn't placed (sleepy phones, new arrivals)
  const loose=[...new Set([...sum.devices.map(d=>d.id),...Object.keys(usedBy),...Object.keys(nowBy)])]
    .filter(id=>!placed.has(id)&&id!==use.self_id&&(stat[id]||(usedBy[id]?.down_bytes+usedBy[id]?.up_bytes)>0));
  if(loose.length) router.children.push({key:"area:loose",kind:"area",role:"loose",name:"Not placed yet",health:LV.unknown,
    children:loose.map(id=>devNode(id,"Not placed yet"))});
  const line=[core.isp,inets[0]].filter(Boolean);
  const worst=line.map(lvl).sort((a,b)=>ORDER.indexOf(b)-ORDER.indexOf(a))[0]??LV.unknown;
  const root={key:"internet",kind:"internet",name:"Internet",health:worst,stat:inets[0],isp:core.isp,children:[router]};
  // traffic flows up: an area carries its devices', the router everything
  const sumUp=n=>{ if(n.children){ const s=n.children.reduce((a,c)=>a+sumUp(c),0); if(n.kind!=="device") n.mbps=s } return n.mbps||0 };
  sumUp(root);
  if(use.current) router.mbps=root.mbps=use.current.down_mbps+use.current.up_mbps;
  return {root,areaOf,unitOf:areaOf,linkOf:{}};   // timing knows the area, not wifi or wired
}

function layout(root){
  // tidy tree: leaves get rows top to bottom, parents sit at the middle of their children
  let row=0, maxDepth=0;
  const walk=(n,d)=>{ n.depth=d; maxDepth=Math.max(maxDepth,d);
    if(n.children&&n.children.length){ n.children.forEach(c=>walk(c,d+1)); n.row=(n.children[0].row+n.children[n.children.length-1].row)/2 }
    else n.row=row++; };
  walk(root,0);
  return {rows:Math.max(row,1),maxDepth};
}

const devCount=n=>n.children.filter(c=>c.kind==="device").length;  // a relay area also holds the area behind it
const width=v=>1.5+Math.min(10,2.2*Math.log2(1+(v||0)));
// a node's marker has its status's shape (as .dot does): circle good, triangle fair, square
// poor, ring no data; this computer is a filled circle in the accent colour
function marker(n,r){
  const {x,y}=n;
  if(n.health===LV.warn){ const k=r*1.25; return `<polygon class="mk" points="${x},${y-k} ${x+k},${y+k*.8} ${x-k},${y+k*.8}" style="fill:var(--c)"></polygon>` }
  if(n.health===LV.bad){ const k=r*.9; return `<rect class="mk" x="${x-k}" y="${y-k}" width="${2*k}" height="${2*k}" rx="1" style="fill:var(--c)"></rect>` }
  if(n.health===LV.unknown) return `<circle class="mk ring" cx="${x}" cy="${y}" r="${r-1}" style="fill:var(--panel)"></circle>`;
  return `<circle class="mk" cx="${x}" cy="${y}" r="${r}" style="fill:var(--c)"></circle>`;
}
const KIND_WORD={internet:"the internet",router:"router",deco:"mesh unit",area:"area",device:"device"};
// what kind of thing a node is, and how many devices hang off it ("mesh unit, 3 devices")
function nodeWhat(n){
  const kind=n.kind==="deco"&&n.node?.role==="main"?"main mesh unit":KIND_WORD[n.kind]||"";
  const count=n.kind==="deco"||n.kind==="area"?devCount(n):null;
  return [kind,count!=null?`${count} device${count===1?"":"s"}`:null].filter(Boolean);
}
// what a screen reader says for a node: "Office, mesh unit, good, 3 devices"
function nodeLabel(n){
  const [kind,...count]=nodeWhat(n);
  return [n.name,kind,n.health==="self"?"this computer":LV_WORD[n.health],...count].filter(Boolean).join(", ");
}
function renderMap(tree,refocus=false){
  const svg=$("#map"), {root}=tree, {rows,maxDepth}=layout(root);
  const hadFocus=svg.contains(document.activeElement)?document.activeElement.dataset?.key:null;
  // narrow screens: tighter columns and shorter labels, so devices stay readable (scrolls if it must)
  const avail=svg.parentElement.clientWidth, narrow=avail<700;
  // LEFT leaves room for the root's label, which sits to the left of its node like other inner labels
  const ROW=34, TOP=24, LEFT=narrow?70:85, LABEL=narrow?175:330, MINCOL=narrow?58:95, MAXNAME=narrow?20:32;
  const W=Math.max(avail,LEFT+LABEL+MINCOL*Math.max(1,maxDepth));
  const colW=(W-LABEL-LEFT)/Math.max(1,maxDepth);
  const nodes=[], edges=[];
  const place=n=>{ n.x=LEFT+(n.kind==="device"?maxDepth:n.depth)*colW; n.y=TOP+n.row*ROW; nodes.push(n);
    (n.children||[]).forEach(c=>{ place(c); edges.push([n,c]) }) };
  place(root);
  const H=TOP+rows*ROW;
  svg.setAttribute("width",W); svg.setAttribute("height",H); svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
  const curve=(a,b)=>{const m=(a.x+b.x)/2;return `M${a.x},${a.y} C${m},${a.y} ${m},${b.y} ${b.x},${b.y}`};
  const sub=n=>n.kind==="device"?[n.network&&n.network!=="main"?ownProp(NETWORK_WORD,n.network):null,n.link&&n.link!=="wired"?BAND[n.link]||null:null,n.stat?.p50!=null?ms(n.stat.p50):null,n.mbps>=0.05?"↓↑ "+mbps(n.mbps):null].filter(Boolean).join(" · ")
    :n.kind==="deco"?[n.node.role==="main"?"main":n.node.backhaul==="wired"?"wired":
                        (b=>b?`${BAND[b.band]||b.band} ${b.rssi} dBm · ${rate(b.rx)}`:"wireless")(bestBand(n.node)),
                      n.mbps>=0.05?mbps(n.mbps):null].filter(Boolean).join(" · ")
    :n.kind==="area"?`${devCount(n)} device${devCount(n)===1?"":"s"}${n.mbps>=0.05?" · "+mbps(n.mbps):""}`
    :n.kind==="router"?[n.stat?.p50!=null?ms(n.stat.p50):null,n.mbps>=0.05?mbps(n.mbps):null].filter(Boolean).join(" · ")
    :n.stat?.p50!=null?ms(n.stat.p50):"";
  // dashes: a radio link (mesh backhaul or WiFi client); dots: not placed; timing branches dashed as before
  const dash=b=>b.edge==="wireless"||b.role==="branch"?"6 4":b.edge==="loose"||b.role==="loose"?"2 4":null;
  svg.innerHTML=edges.map(([a,b])=>`<path class="edge ${b.health}" d="${curve(a,b)}" style="stroke:var(--c);stroke-width:${width(b.mbps)}${dash(b)?";stroke-dasharray:"+dash(b):""}"></path>`).join("")+
    nodes.map(n=>{const leaf=!n.children||!n.children.length, r=n.kind==="device"?5:8;
      // leaves: label to the right. Inner nodes: label just left of the node, above and below
      // its incoming line - the one spot no line crosses (children leave to the right, the
      // parent's line arrives level from the left)
      const tx=leaf?n.x+12:n.x-12, ty=leaf?n.y+4:n.y-8, anchor=leaf?"start":"end";
      return `<g class="node ${n.health}${n.key===selected?" sel":""}" data-key="${esc(n.key)}" tabindex="0" role="button" aria-label="${esc(nodeLabel(n))}">
        <title>${esc(n.name)}</title>${marker(n,r)}
        <text x="${tx}" y="${ty}" text-anchor="${anchor}" class="${leaf?"":"area"}">${esc(n.name.length>MAXNAME?n.name.slice(0,MAXNAME-1)+"…":n.name)}${leaf&&sub(n)&&!narrow?`<tspan class="sub" dx="8">${esc(sub(n))}</tspan>`:""}</text>
        ${!leaf&&sub(n)?`<text x="${n.x-12}" y="${n.y+16}" text-anchor="end" class="sub">${esc(sub(n))}</text>`:""}</g>`}).join("");
  tree.byKey={...tree.byKey,...Object.fromEntries(nodes.map(n=>[n.key,n]))};   // indexTree's extras kept
  svg.querySelectorAll(".node").forEach(g=>{ const pick=()=>{
      // an open rename (map pane or devices table) is cancelled the normal way: its blur
      // handler resets `editing` and refreshes, so nothing is left half-open
      document.querySelector("input.namebox")?.blur();
      panelOpener=g; go({item:keyItem(g.dataset.key)})};   // the side panel; Back closes it
    g.onclick=pick; g.onkeydown=e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();pick()}} });
  // the SVG is redrawn every refresh: keep keyboard focus where it was, without scrolling the
  // page back up to the map while you're reading further down
  if(hadFocus||refocus) [...svg.querySelectorAll(".node")].find(g=>g.dataset.key===(hadFocus||selected))?.focus({preventScroll:true});
  renderMapList(tree);
}

// the map as a nested list - what a screen reader reads, and the "Show as list" view: each entry
// opens the side panel like its node does
function renderMapList(tree){
  const ul=$("#maplist"), hadFocus=ul.contains(document.activeElement)?document.activeElement.dataset?.key:null;
  const entry=n=>{ const it=keyItem(n.key), sub=n.kind==="device"?null:nodeWhat(n).join(", ");   // the dot says the status
    const name=validItem(it)?`<a class="itemlink" data-key="${esc(n.key)}"${mapAsList?"":' tabindex="-1"'} href="${esc(hashFor(tab,rangeLabel(),null,it))}">${esc(n.name)}</a>`:esc(n.name);
    const kids=(n.children||[]).map(entry).join("");
    return `<li><span class="dot ${n.health}"></span>${name}${sub?` <span class="sub">${esc(sub)}</span>`:""}${kids?`<ul>${kids}</ul>`:""}</li>` };
  // only when it changed: a screen reader reading the list keeps its place across refreshes
  const html=entry(tree.root); if(ul.dataset.html===html) return;
  ul.innerHTML=html; ul.dataset.html=html;
  if(hadFocus) [...ul.querySelectorAll("a.itemlink")].find(a=>a.dataset.key===hadFocus)?.focus({preventScroll:true});
}
let mapAsList=false;
try{ mapAsList=localStorage.getItem("hearth_maplist")==="1" }catch(e){}
function showMapAsList(on){
  mapAsList=on; save("hearth_maplist",on?"1":"0");
  $("#maplist").classList.toggle("sr-only",!on); $("#mapscroll").hidden=on;
  $("#maplistbtn").textContent=on?"Show as map":"Show as list";   // the label says what it does (no aria-pressed)
  // hidden links are skipped by Tab (the map's nodes are the keyboard way in); a map drawn while
  // hidden had no width, so draw it again now it shows
  if(latestTree){ if(!on) renderMap(latestTree); else renderMapList(latestTree) }
}

// where a device has been (its unit over time, from the server's record): fetched once a
// minute at most per device, then the panel is redrawn with it
const placeCache={};
let latestTree=null;   // the map as last drawn: a late answer redraws the panel from it, never an older one
function placesHtml(id,tree){
  const c=placeCache[id];
  if(!c||Date.now()-c.at>60000){
    placeCache[id]={at:Date.now(),html:c?.html??'<span class="muted small">…</span>'};
    const failed=()=>{ placeCache[id]={at:Date.now(),html:'<span class="muted small">could not load - retrying in a minute</span>'};
      if(selected===id) renderDetail(latestTree||tree) };
    fetch(`/api/device/places?id=${encodeURIComponent(id)}&minutes=576000`).then(r=>r.ok?r.json():null).then(d=>{
      if(!d) return failed();
      // the server lists places oldest first: the last five, newest first
      const rows=d.places.slice(-5).reverse().map(p=>`${esc(p.node_name||"Location unknown")} <span class="muted small">${
        p.how==="mesh"?"(mesh) ":p.how==="timing"?"(by timing) ":""}since ${esc(new Date(p.ts*1000).toLocaleString())}</span>`);
      placeCache[id]={at:Date.now(),html:rows.length?rows.join("<br>"):'<span class="muted small">not recorded yet</span>'};
      if(selected===id) renderDetail(latestTree||tree);
    }).catch(failed);
  }
  return placeCache[id].html;
}

function renderDetail(tree){
  const n=tree.byKey[selected];   // renderPanel only calls this for an item it found
  if(!n) return;
  const kv=rows=>`<dl class="kv">${rows.filter(r=>r[1]!=null&&r[1]!=="").map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const lat=s=>s?[["Latency",`${ms(s.p50)} median · ${ms(s.p95)} p95`],["Loss",pc(s.loss_pct)],["Spikes",s.spikes]]:[];
  let html;
  if(n.kind==="device"){
    const i=n.info||{}, u=n.used, w=n.now;
    html=`<h3>${esc(n.name)}${n.self?"":renameBtn(n.id,n.name)}</h3>`+kv([
      ["Area",esc(tree.areaOf[n.id]||"")],["Type",n.devkind?esc(kindIcon(n.devkind)+(ownProp(KIND_WORD_OF,n.devkind)||n.devkind)):null],
      ["Network",n.network?esc(ownProp(NETWORK_WORD,n.network)||n.network):null],
      ["Location",n.placementWhy?`${tree.areaOf[n.id]?.endsWith("probably")?"probably · ":""}<span class="muted small">${esc(n.placementWhy)}</span>`:null],
      ["Where it's been",n.id?.startsWith("dev:")?placesHtml(n.id,tree):null],
      ["Connection",n.quality?`<span class="tag ${n.health}" title="${esc(n.qualityWhy||"")}">${esc(n.quality==="sleepy"?"power saving":n.quality)}</span> <span class="muted small">${esc(n.qualityWhy||"")}</span>`:null],
      ["Address",esc([n.ip||i.ip,n.mac||i.mac].filter(Boolean).join(" · "))],
      ["Also answers at",n.alsoAt?esc(n.alsoAt.join(", "))+' <span class="muted small">(a second address on the same network card)</span>':null],
      ["Model",esc(i.model||i.vendor||"")],...lat(n.stat),
      ["Internet now",w?`↓ ${mbps(w.down_mbps)} · ↑ ${mbps(w.up_mbps)}`:null],
      [`Used (${rangeLabel()})`,u?`↓ ${fmtB(u.down_bytes)} · ↑ ${fmtB(u.up_bytes)}`:null],
      ["Peak",u?.peak_down_mbps!=null?`↓ ${mbps(u.peak_down_mbps)}`:null],
      ["Seen",i.last_seen?(i.state||(i.online?"online":"offline"))+" · "+ago(i.last_seen):null]]);
  } else if(n.kind==="deco"){
    const i=n.info||{};
    html=`<h3>${esc(n.name)}</h3>`+kv([["Mesh node",esc([n.node.model,n.node.role==="main"?"main unit":"satellite"].filter(Boolean).join(" · "))],
      ["Uplink",esc(uplinkText(n.node))],
      ...(n.node.bands||[]).filter(b=>n.node.rssi?.[b]!=null).map(b=>[BAND[b]||b,
        `<span class="tag ${LV[n.node.band_levels?.[b]]??""}">${n.node.rssi[b]} dBm</span> ↓${esc(rate(n.node.rate_rx?.[b]))} ↑${esc(rate(n.node.rate_tx?.[b]))}`+
        (n.node.usual_rx?.[b]?` <span class="muted small">usually ↓${esc(rate(n.node.usual_rx[b]))}</span>`:"")]),
      ["Address",esc(n.node.ip||i.ip||"")],...lat(n.stat),
      ["Devices",devCount(n)],["Internet now",n.mbps>=0.05?mbps(n.mbps):"idle"],
      ["Status",n.node.online?"connected":"<span class=\"tag bad\">off the mesh</span>"]])+
      `<div class="small muted" style="margin-top:8px">${esc(n.children.filter(c=>c.kind==="device").map(c=>c.name).join(", "))}</div>`;
  } else if(n.kind==="area"){
    html=`<h3>${esc(n.title||n.name)}${n.group!=null?renameBtn("grp:"+n.group,n.name):""}</h3>`+kv([
      ["Devices",devCount(n)],...lat(n.stat),["Internet now",n.mbps>=0.05?mbps(n.mbps):"idle"]])+
      (n.note?`<p class="small muted" style="margin:8px 0 0">${esc(n.note)}</p>`:"")+
      `<div class="small muted" style="margin-top:8px">${esc(n.children.filter(c=>c.kind==="device").map(c=>c.name).join(", "))}</div>`;
  } else if(n.kind==="router"){
    html=`<h3>Router</h3>`+kv([...lat(n.stat),["Internet now",last?.use?.current?`↓ ${mbps(last.use.current.down_mbps)} · ↑ ${mbps(last.use.current.up_mbps)}`:null],
      ...linkRows(routerLink)]);
  } else {
    html=`<h3>Internet</h3>`+kv([["Broadband line",n.isp?`${ms(n.isp.p95)} p95 · ${pc(n.isp.loss_pct)} loss`:null],...lat(n.stat)]);
  }
  $("#detail").innerHTML=html;
  $("#detail h3")?.setAttribute("id","panel-title");
}

// the router's own view of its internet connection and traffic shaping (#122); rows kv() leaves
// out when there's no reading (a router Hearth can't read, or a firmware without them)
let routerLink=null;
const PROTO={pppoe:"PPPoE",dhcp:"DHCP",static:"static address"};
function shapingText(q){
  if(!q) return null;
  if(!q.enabled) return "off";
  return `${q.down_mbps!=null?`↓ ${mbps(q.down_mbps)}`:"↓ –"} · ${q.up_mbps!=null?`↑ ${mbps(q.up_mbps)}`:"↑ –"}${q.qdisc?` (SQM, ${q.qdisc})`:" (SQM)"}`;
}
function linkRows(l){
  const w=l?.wan;
  // kv() writes values as HTML: escaped here, though the server already checked each one
  const e=v=>v==null?null:esc(v);
  return [["Connection",e(w?`${PROTO[w.protocol]||w.protocol||"–"} · ${w.connected?"connected":"not connected"}`:null)],
          ["Internet address",e(w?.ip||null)],["Traffic shaping",e(shapingText(l?.sqm))]];
}

// ---------------------------------------------------------------- side panel
// One <dialog> for whatever item= names: docked beside the page on a wide screen, modal and
// full-screen on a phone. The address is the truth: opening is go({item}), closing removes it.
const MAP_DATA=["summary","usage","devices","mesh"];   // what the side panel's items are built from
const narrowScreen=()=>matchMedia("(max-width:700px)").matches;
// every item the panel can show: the map's nodes, plus each known device the map doesn't draw
// (offline ones), so a device in the Devices table always opens
function indexTree(tree,sum,use,dev){
  const byKey={}, walk=n=>{ byKey[n.key]=n; (n.children||[]).forEach(walk) };
  walk(tree.root);
  const stat=Object.fromEntries(sum.devices.map(d=>[d.id,d])), info=devInfo(dev);
  const nowBy=Object.fromEntries((use.current?.devices||[]).map(d=>[d.id,d]));
  const usedBy=Object.fromEntries((use.window?.devices||[]).map(d=>[d.id,d]));
  for(const id of new Set([...dev.map(d=>d.id),...Object.keys(usedBy)])) if(!byKey[id])
    byKey[id]={key:id,kind:"device",id,name:stat[id]?.name||info[id]?.name||usedBy[id]?.name||id,
               health:lvl(stat[id]),stat:stat[id],now:nowBy[id],used:usedBy[id],info:info[id],self:id===use.self_id,children:[]};
  tree.byKey=byKey; return tree;
}
// the smallest range that holds an episode starting at `start` (the panel asks for that much)
const rangeFor=start=>{ const age=((lastStatus?.updated??Date.now()/1000)-start)/60+15;
  return (RANGES.find(r=>r[1]>=age)||RANGES[RANGES.length-1]) };
function renderEpisode(e){
  const [label]=rangeFor(e.start), slot=Math.floor(e.start/900)*900;
  $("#detail").innerHTML=`<h3 id="panel-title">${e.truncated?"Before ":""}${esc(new Date(e.start*1000).toLocaleString())}</h3>`+
    `<p><span class="tag ${LV[e.level]??""}">${esc(e.cause)}</span></p><dl class="kv">`+
    `<dt>Length</dt><dd>${esc(span(e.duration_s))}</dd><dt>Bursts</dt><dd>${e.clusters|0}</dd>`+
    `<dt>Lost</dt><dd>${e.lost_s?`${e.lost_s|0} s`:"nothing"}</dd></dl>`+
    (e.context||[]).map(c=>`<div class="muted small">${esc(c)}</div>`).join("")+
    `<p class="small"><a href="${esc(hashFor("history",label,slot,null))}">Show it in History</a></p>`;
}
const ownProp=(o,k)=>o&&Object.hasOwn(o,k)?o[k]:undefined;   // a lookup by a name from the address
function renderSource(name,s){
  $("#detail").innerHTML=`<h3 id="panel-title">${esc(ownProp(SOURCE_NAMES,name)||name)}</h3><dl class="kv">`+
    `<dt>State</dt><dd>${sourceState(s)}</dd>`+
    (sourceWhy(s)?`<dt>Detail</dt><dd>${esc(sourceWhy(s))}</dd>`:"")+
    (s.last_ok?`<dt>Last worked</dt><dd>${esc(new Date(s.last_ok*1000).toLocaleString())}</dd>`:"")+`</dl>`;
}
// ctx: the data loaded - {tree, eps, sources}, each absent while it loads; failed: the item's
// data couldn't be loaded
function renderPanel(ctx,failed=false){
  const dlg=$("#panel");
  if(!item&&!panelNote){ if(dlg.open) dlg.close(); return }
  const kind=itemKind(item), data=kind==="ep"?ctx?.eps:kind==="src"?ctx?.sources:kind==="alerts"?ctx?.alerts:ctx?.tree;
  const found=!item||!data?null:kind==="alerts"?data:kind==="ep"?data.find(e=>Math.trunc(e.start)===+item.slice(3))
             // own properties only: src:constructor must be "not found", not Object.prototype's
             :kind==="src"?ownProp(data,item.slice(4)):ownProp(data.byKey,itemKey(item));
  if(item&&(!data||failed)){
    // never drop a link because its data didn't arrive: say so, keep it, retry on the next refresh
    $("#detail").innerHTML=failed?`<h3 id="panel-title">Couldn't load this item</h3><p class="muted small">Retrying…</p>`
                                 :`<h3 id="panel-title">Loading…</h3>`;
  } else if(item&&!found){
    // the data loaded without it: drop it from the address (no new history entry) and say why
    panelNote=kind==="ep"?"That slowdown or outage isn't in Hearth's history any more."
      :kind==="src"?"Hearth has no data source by that name."
      :"Hearth doesn't know that item any more - it may have left the network, or the link is old.";
    item=selected=null; history.replaceState(null,"",hashFor(tab,rangeLabel(),at,null));
  } else if(kind==="ep") renderEpisode(found);
  else if(kind==="src") renderSource(item.slice(4),found);
  else if(kind==="alerts") renderAlerts(found);
  else if(item){ selected=itemKey(item); renderDetail(data) }
  if(!item&&panelNote) $("#detail").innerHTML=`<h3 id="panel-title">Not found</h3><p class="muted small">${esc(panelNote)}</p>`;
  if(!dlg.open){ narrowScreen()?dlg.showModal():dlg.show() }
}
function closePanel(){
  const dlg=$("#panel"), opener=panelOpener; panelNote=null;
  if(dlg.open) dlg.close();
  // a new history entry, like every view change: Back after closing reopens the panel
  if(item) go({item:null});
  panelOpener=opener;   // go() cleared it; restore focus from what was recorded at opening
  // the map is redrawn every refresh, so the node that opened the panel may be a new element
  const back=panelOpener?.isConnected?panelOpener
    :panelOpener?.dataset?.key?[...document.querySelectorAll("[data-key]")].find(g=>g.dataset.key===panelOpener.dataset.key&&g.tagName===panelOpener.tagName):null;
  back?.focus({preventScroll:true}); panelOpener=null;
}
$("#panel-close").onclick=closePanel;
// some browsers (Safari) don't focus a link when it's clicked: record the opener on the click
document.addEventListener("click",e=>{ const a=e.target.closest?.("a.itemlink"); if(a) panelOpener=a },true);
$("#panel").addEventListener("cancel",e=>{ e.preventDefault(); closePanel() });   // Escape on the modal form
document.addEventListener("keydown",e=>{ if(e.key==="Escape"&&$("#panel").open&&!e.defaultPrevented&&!e.target.closest?.("input")) closePanel() });

// ---------------------------------------------------------------- traffic
function renderTraffic(u){
  if(!u.available){
    if(trafficChart){trafficChart.destroy();trafficChart=null}
    if(trafficUpChart){trafficUpChart.destroy();trafficUpChart=null}
    $("#usagerefresh").hidden=true; $("#usagewhen").textContent="";
    $("#trafficbody").innerHTML=`<p class="muted">Hearth isn't reading your router. With a GL.iNet router (firmware 4.x), put the admin password in
      <code>.hearth/router.env</code> in your home folder (or the file named by <code>router_credentials_file</code>) as
      <code>GLINET_PASSWORD=…</code> and restart Hearth.</p>`;
    return;
  }
  $("#usagerefresh").hidden=!!u.error;  // while failing, retries are on a back-off
  const c=u.current, w=u.window;
  $("#usagewhen").textContent=u.error?`can't read the router since ${new Date(u.error.since*1000).toLocaleTimeString()} (${u.error.error})`
    :c?`from the router, ${ago(c.ts)}`:"waiting for a reading…";
  // a period that began before recording did only covers part of it: say from when
  const from=start=>u.recording_since>start+60?` <span class="small muted">since ${new Date(u.recording_since*1000).toLocaleString([],{weekday:start<u.now-86400?"short":undefined,hour:"2-digit",minute:"2-digit"})}</span>`:"";
  const midnight=new Date(); midnight.setHours(0,0,0,0);
  const pair=(d,up)=>`↓ ${d} · ↑ ${up}`;
  $("#trafficbody").innerHTML=`<div class="sum">
      <span>Now<b>${c?pair(mbps(c.down_mbps),mbps(c.up_mbps)):"–"}</b></span>
      <span>Last ${rangeLabel()}<b>${w?pair(fmtB(w.down_bytes),fmtB(w.up_bytes)):"–"}</b>${from(u.now-minutes*60)}</span>
      <span>Today<b>${pair(fmtB(u.today?.down_bytes),fmtB(u.today?.up_bytes))}</b>${from(midnight/1000)}</span>
      <span>7 days<b>${pair(fmtB(u.week?.down_bytes),fmtB(u.week?.up_bytes))}</b>${from(u.now-7*86400)}</span>
    </div><div id="trafficpick" class="pick"></div>
    <div class="charthead">Download</div><div class="chartbox"><canvas id="trafficdown"></canvas></div>
    <div class="charthead">Upload</div><div class="chartbox"><canvas id="trafficup"></canvas></div>
    <div class="small muted" style="margin-top:6px">By device, each chart on its own scale. Untick a device to hide it, or "only" to see one on its own.
      Internet traffic only: copies between devices at home don't pass the router.</div>`;
  renderTrafficCharts(u);
}
const trafficShown=k=>trafficOnly?k===trafficOnly:!trafficHidden.has(k);
function setTrafficFilter(hidden,only){
  trafficHidden=hidden; trafficOnly=only;
  // unticked devices that aren't charted right now are kept, so a quiet device stays hidden when it
  // comes back; only the most recent TRAFFIC_HIDDEN_MAX are remembered, so the list can't grow forever
  save("hearth_traffic_hidden",JSON.stringify([...hidden].slice(-TRAFFIC_HIDDEN_MAX))); save("hearth_traffic_only",only||"");
  if(last?.use?.available) renderTrafficCharts(last.use);
}
// a stacked traffic chart: a device with no readings for a while used nothing then, so it drops to
// zero at the gap's edges - never a straight band from its last reading to its next (as #81 for latency)
function zeroGaps(points,bucket){
  const out=[];
  points.forEach((p,i)=>{
    const prev=points[i-1];
    if(prev&&bucket&&p[0]-prev[0]>bucket*1.5) out.push([prev[0]+bucket,0,0],[p[0]-bucket,0,0]);
    out.push(p);
  });
  return out;
}
function renderTrafficCharts(u){
  const s=u.series||{by_device:[],bucket_s:60}, half=s.bucket_s/2;
  const devs=s.by_device.map((d,i)=>({key:trafficKey(d),name:d.name||"Everything else",col:d.id?COLORS[i%COLORS.length]:OTHER,points:zeroGaps(d.points,s.bucket_s)}));
  // isolated on a device that isn't among the busiest in this period: keep your choice, and say why it's empty
  const missing=trafficOnly&&!devs.some(d=>d.key===trafficOnly);
  // the list is rebuilt below: remember which control had keyboard focus, to give it back after
  const pick=$("#trafficpick"), had=pick.contains(document.activeElement)?document.activeElement:null;
  const refocus=had&&{tag:had.tagName,key:had.dataset.key,all:had.dataset.all};
  pick.innerHTML=(missing?`<span class="small muted">The device you picked isn't among the busiest in this period.</span>`:"")+devs.map(d=>`<span class="pickitem"><label><input type="checkbox" data-key="${esc(d.key)}"${trafficShown(d.key)?" checked":""}>
      <i style="background:${d.col}"></i>${esc(d.name)}</label><button class="pickonly" data-key="${esc(d.key)}"${trafficOnly===d.key?" disabled":""}>only</button></span>`).join("")
    +(trafficOnly||devs.some(d=>trafficHidden.has(d.key))?`<button class="pickonly" data-all="1">show all</button>`:"");
  $("#trafficpick").querySelectorAll("input").forEach(b=>b.onchange=()=>{
    // unticking while isolated: start from "just that one shown" and carry on from there. Only the
    // devices charted now are hidden; anyone joining the busiest list later is shown
    const hidden=trafficOnly?new Set(devs.map(d=>d.key).filter(k=>k!==trafficOnly)):new Set(trafficHidden);
    b.checked?hidden.delete(b.dataset.key):hidden.add(b.dataset.key);
    setTrafficFilter(hidden,null) });
  $("#trafficpick").querySelectorAll("button").forEach(b=>b.onclick=()=>
    b.dataset.all?setTrafficFilter(new Set(),null):setTrafficFilter(trafficHidden,b.dataset.key));
  if(refocus){  // the same control by what it does (data-key / data-all), not by position
    // the same control if it's still usable; pressing "only" disables that button, so then the
    // same device's tickbox; only then the first control
    const again=[...pick.querySelectorAll(refocus.tag)].find(e=>refocus.all?e.dataset.all:e.dataset.key===refocus.key);
    const box=refocus.key&&[...pick.querySelectorAll("input")].find(e=>e.dataset.key===refocus.key);
    (again&&!again.disabled?again:box||pick.querySelector("input,button:not([disabled])"))?.focus({preventScroll:true});
  }
  const shown=devs.filter(d=>trafficShown(d.key));
  const chart=(old,canvas,col)=>{
    if(old) old.destroy();  // the canvas was just re-rendered
    return new Chart(canvas,{type:"line",data:{datasets:shown.map(d=>({label:d.name,data:d.points.map(p=>({x:p[0]+half,y:p[col]})),
        backgroundColor:d.col+"aa",borderColor:d.col,borderWidth:1,pointRadius:0,fill:true}))},
      options:{animation:false,maintainAspectRatio:false,parsing:false,interaction:{mode:"index",intersect:false},
        plugins:{legend:{display:false},
          tooltip:{filter:i=>i.parsed.y>=0.05,callbacks:{title:it=>fmtT(it[0].parsed.x),label:x=>`${x.dataset.label}: ${mbps(x.parsed.y)}`}}},
        scales:{x:{type:"linear",min:u.now-minutes*60,max:u.now,ticks:{color:CC.muted,maxTicksLimit:8,callback:v=>fmtT(v)},grid:{color:CC.grid}},
                y:{stacked:true,beginAtZero:true,ticks:{color:CC.muted},grid:{color:CC.grid},title:{display:true,text:"Mb/s",color:CC.muted}}}}});
  };
  trafficChart=chart(trafficChart,$("#trafficdown"),1);
  trafficUpChart=chart(trafficUpChart,$("#trafficup"),2);
}

// a mesh unit's certificate changed: Hearth stopped sending it the password until you decide
function renderTrust(m){
  const p=m.pending_cert, box=$("#meshtrust");
  if(!p){ box.innerHTML=""; return }
  const fp=s=>s.slice(0,8).toUpperCase()+"…"+s.slice(-8).toUpperCase();
  const who=esc((p.name?p.name+" · ":"")+p.host);
  const mac=p.same_device?`<span class="tag good">same device</span> its network address (MAC ${esc(p.mac_now)}) hasn't changed`
    :p.mac_now?`<span class="tag bad">different device?</span> the network address there is now ${esc(p.mac_now)}, was ${esc(p.mac_before||"unknown")}`
    :`<span class="tag warn">can't check</span> the device's network address isn't known`;
  // the server says why it didn't accept the change by itself; the page only words the two kinds
  const keys=p.kind==="keys";
  box.innerHTML=`<div class="panel" style="border-color:var(--warn);margin-bottom:12px">
    <b>Your mesh's main unit (${who}) ${keys?"offered different login keys":"presented a new security certificate"}</b> <span class="muted small">${ago(p.since)}</span>
    <div class="small" style="margin:6px 0">Hearth stopped reading the mesh and sent it nothing - including your password - until you decide.
      ${keys?"Its login keys protect your password. They change when a unit is reset or replaced - or when another device is pretending to be it."
            :"Its login keys are what Hearth checks, and new certificates with the same keys are normally accepted by themselves."}</div>
    ${p.reason?`<div class="small">Not accepted by itself because ${esc(p.reason)}.</div>`:""}
    <div class="small">${mac}</div>
    <div class="muted small" style="margin:4px 0 8px">${keys?`login keys changed; certificate ${p.old===p.new?fp(p.new)+" unchanged":fp(p.old)+" → "+fp(p.new)}`:`certificate ${fp(p.old)} → ${fp(p.new)}`}</div>
    <button class="btn" id="trustbtn">${keys?"Trust the new keys":"Trust the new certificate"}</button>
    <span class="muted small">Only if you expected this (${keys?"a reset or replaced unit":"a restart or update"}) and the device looks the same.</span></div>`;
  $("#trustbtn").onclick=async()=>{
    const b=$("#trustbtn"); b.disabled=true; b.textContent="Trusting…";
    const r=await fetch("/api/mesh/trust",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({host:p.host,fingerprint:p.new})}).catch(()=>null);
    if(!r||!r.ok){ b.textContent="Couldn't confirm - reload the page"; return }
    b.textContent="Trusted - reading the mesh…";
    setTimeout(()=>refresh().catch(()=>{}),6000);
  };
}

// ---------------------------------------------------------------- mesh & WiFi quality
let meshChart;
function renderMesh(m){
  $("#meshpanel").hidden=!m.available;
  if(!m.available) return;
  const nodeName=Object.fromEntries(m.nodes.map(n=>[n.mac,n.name||n.mac]));
  const sats=m.nodes.filter(n=>n.role!=="main");
  const wireless=m.devices.filter(d=>d.link&&d.link.startsWith("band")).sort((a,b)=>
    ORDER.indexOf(lvl(b))-ORDER.indexOf(lvl(a)));
  // "healthy" only when there was something to judge: at least one measured radio link
  const measured=sats.some(n=>n.backhaul==="wireless"&&Object.keys(n.rssi||{}).length);
  $("#meshbody").innerHTML=(m.findings.length?m.findings.map(f=>`<div style="margin-bottom:6px"><span class="tag ${LV[f.level]??""}">${f.level==="bad"?"problem":"warning"}</span> ${esc(f.text)}</div>`).join("")
      :measured?`<div style="margin-bottom:6px"><span class="tag good">healthy</span> <span class="muted small">every wireless mesh link is strong</span></div>`:"")+
    `<div class="grid2" style="margin-top:10px">
      <div><h3 style="margin:0 0 6px;font-size:13px">Mesh links</h3><table><thead><tr><th>Unit</th><th>Link</th><th class="num">Signal</th><th class="num">Speed ↓ / ↑</th></tr></thead><tbody>
      ${m.nodes.map(n=>{
        if(n.role==="main") return `<tr><td>${esc(n.name)}</td><td colspan="3" class="muted">main unit · cable to the router</td></tr>`;
        if(n.backhaul==="wired") return `<tr><td>${esc(n.name)}</td><td colspan="3" class="muted">cable to ${esc(nodeName[n.parent]||"the main unit")}</td></tr>`;
        return (n.bands||[]).map((b,i)=>`<tr><td>${i?"":esc(n.name)}</td><td>${esc(BAND[b]||b)}${i?"":` <span class="muted small">to ${esc(nodeName[n.parent]||"main")}</span>`}</td>
          <td class="num">${n.rssi?.[b]!=null?`<span class="tag ${LV[n.band_levels?.[b]]??""}">${n.rssi[b]} dBm</span>`:"–"}</td>
          <td class="num">${esc(rate(n.rate_rx?.[b]))} / ${esc(rate(n.rate_tx?.[b]))}</td></tr>`).join("");
      }).join("")}</tbody></table>
      <div class="chartbox small" style="margin-top:8px"><canvas id="meshchart"></canvas></div>
      <div class="muted small">Signal: −65 dBm or better is good, down to −75 fair, below that weak.</div></div>
      <div><h3 style="margin:0 0 6px;font-size:13px">Wireless devices</h3><div class="scroll" style="max-height:360px"><table><thead><tr><th>Device</th><th>On</th><th>Connection</th></tr></thead><tbody>
      ${wireless.map(d=>`<tr><td>${esc(kindIcon(d.kind)+d.name)}</td><td>${esc(nodeName[d.node]||"")} <span class="muted small">${esc(BAND[d.link]||d.link)}</span></td>
        <td>${d.quality?`<span class="tag ${lvl(d)}" title="${esc(d.why||"")}">${esc(d.quality==="sleepy"?"power saving":d.quality)}</span>`:"–"}<div class="muted small">${esc(d.quality_why||"")}</div></td></tr>`).join("")
        ||`<tr><td colspan="3" class="muted">No wireless devices right now.</td></tr>`}
      </tbody></table></div>
      <div class="muted small" style="margin-top:6px">The mesh doesn't report each device's signal, so this is judged from Hearth's own pings over the last hour: lost answers, and how much slower the device is than the unit it's on.</div></div>
    </div>`;
  const ds=[]; let i=0;
  for(const n of sats) for(const b of n.bands||[]){
    const pts=m.history.series[`${n.mac}|${b}`]; if(!pts) continue;
    const col=COLORS[i++%COLORS.length];
    ds.push({label:`${n.name} ${BAND[b]||b}`,data:pts.map(p=>({x:p[0]+m.history.bucket_s/2,y:p[1]})),borderColor:col,backgroundColor:col+"30",borderWidth:1.3,pointRadius:0});
  }
  if(meshChart) meshChart.destroy();
  meshChart=new Chart($("#meshchart"),{type:"line",data:{datasets:ds},options:{animation:false,maintainAspectRatio:false,parsing:false,
    interaction:{mode:"index",intersect:false},plugins:{legend:{labels:{color:CC.text,boxWidth:10,font:{size:11}}},
      tooltip:{callbacks:{title:it=>fmtT(it[0].parsed.x),label:x=>`${x.dataset.label}: ${x.parsed.y} dBm`}}},
    scales:{x:{type:"linear",min:Date.now()/1000-minutes*60,max:Date.now()/1000,ticks:{color:CC.muted,maxTicksLimit:6,callback:v=>fmtT(v)},grid:{color:CC.grid}},
            y:{suggestedMin:-80,suggestedMax:-40,ticks:{color:CC.muted},grid:{color:CC.grid},title:{display:true,text:"dBm",color:CC.muted}}}}});
}

// ---------------------------------------------------------------- the computer running Hearth
let hostChart;
const gib=b=>b==null?"–":(b/2**30).toFixed(b>=10*2**30?0:1)+" GB";
function renderHost(h){
  $("#hostpanel").hidden=!h.available;
  if(!h.available) return;
  const c=h.current, up=c.uptime_s;
  $("#hostbody").innerHTML=(h.warnings.length?h.warnings.map(w=>`<div style="margin-bottom:6px"><span class="tag ${LV[w.level]??""}">${w.level==="info"?"note":w.level==="bad"?"problem":"warning"}</span> ${esc(w.text)}</div>`).join(""):
      `<div style="margin-bottom:6px"><span class="tag good">healthy</span> <span class="muted small">nothing unusual</span></div>`)+
    `<div class="sum" style="margin-top:10px">
      <span>CPU<b>${c.cpu_pct==null?"–":Math.round(c.cpu_pct)+"%"}</b></span>
      <span>Memory in use<b>${gib(c.mem_total-c.mem_avail)} of ${gib(c.mem_total)}</b></span>
      <span title="Memory programs have reserved. Near the limit, Windows slows and programs fail even with RAM free.">Reserved<b>${gib(c.commit)} of ${gib(c.commit_limit)}</b></span>
      <span title="Kernel memory that can't be paged out; usually well under 1 GB">Kernel memory<b>${gib(c.pool_nonpaged)} + ${gib(c.pool_paged)}</b></span>
      <span>Handles<b>${(c.handles||0).toLocaleString()}</b></span>
      ${up!=null?`<span>Up<b>${Math.floor(up/86400)}d ${Math.floor(up%86400/3600)}h</b></span>`:""}
    </div>
    <div class="chartbox small"><canvas id="hostchart"></canvas></div>
    <div class="scroll" style="margin-top:10px"><table><thead><tr><th>Program</th><th class="num">Reserved memory</th><th class="num">Change (${esc(rangeLabel())})</th><th class="num">Handles</th></tr></thead><tbody>
    ${h.processes.map(p=>`<tr><td>${esc(p.name)}${p.count>1?` <span class="muted small">×${p.count}</span>`:""}</td><td class="num">${gib(p.private)}</td>
      <td class="num">${p.change==null||Math.abs(p.change)<0.05*2**30?"–":`<span class="${p.change_level?"tag "+LV[p.change_level]:""}">${p.change>=0?"+":"−"}${gib(Math.abs(p.change))}</span>`}</td>
      <td class="num">${p.handles_level?`<span class="tag ${LV[p.handles_level]}">${p.handles.toLocaleString()}</span>`:p.handles.toLocaleString()}</td></tr>`).join("")}
    </tbody></table></div>`;
  const pts=h.series.points, half=h.series.bucket_s/2;
  const line=(label,i,col)=>({label,data:pts.map(p=>({x:p[0]+half,y:p[i]})),borderColor:col,backgroundColor:col+"30",borderWidth:1.3,pointRadius:0,fill:false});
  if(hostChart) hostChart.destroy();
  hostChart=new Chart($("#hostchart"),{type:"line",data:{datasets:[line("CPU %",1,CC.blue),line("Memory in use %",3,CC.teal),line("Reserved % of limit",2,CC.orange)]},
    options:{animation:false,maintainAspectRatio:false,parsing:false,interaction:{mode:"index",intersect:false},
      plugins:{legend:{labels:{color:CC.text,boxWidth:12}},tooltip:{callbacks:{title:it=>fmtT(it[0].parsed.x),label:x=>`${x.dataset.label}: ${x.parsed.y==null?"–":x.parsed.y.toFixed(0)+"%"}`}}},
      scales:{x:{type:"linear",min:h.now-minutes*60,max:h.now,ticks:{color:CC.muted,maxTicksLimit:8,callback:v=>fmtT(v)},grid:{color:CC.grid}},
              y:{min:0,max:100,ticks:{color:CC.muted},grid:{color:CC.grid}}}}});
}

// ---------------------------------------------------------------- everything else
// header: three fenced cells; live figures have their own strip below, so none here
// the header, on every tab, from /api/status: the last hour's slowdowns, the verdict, the route
function renderStatus(st){
  if(!st) return;
  const set=(id,html,title)=>{ const e=$("#"+id); e.innerHTML=html; e.title=title??e.textContent };
  set("st-inc",`<span class="dot ${LV[st.episodes_level_1h]??LV.ok}"></span>${(st.episodes_1h||0).toLocaleString()}`,
      st.episodes_breakdown_1h||"none");
  set("st-verdict",st.verdict?`<span class="dot ${LV[st.verdict_level]??""}"></span>${esc(st.verdict)}`:"–",st.verdict);
  set("st-route",st.path?esc(st.path):"learning the layout…");
}

// second row: slower headline figures. Levels (colours) come from the server, which owns the thresholds
function renderKpi(k){
  const put=(id,level,text,sub,title,why)=>{
    const b=$("#kp-"+id); b.innerHTML=(level&&LV[level]?`<span class="dot ${LV[level]}"></span>`:"")+esc(text);
    b.title=(title||text)+(why?`\n${why}`:"");
    const s=$(`#kp-${id}-sub`); if(s){ s.textContent=sub||""; s.title=sub||"" } };
  if(!k){ ["router","inet","today","mesh","wifi","calls"].forEach(id=>put(id,null,"–","")); return }
  // (step 4.3b) how a call would sound now, from the pings to the internet: a MOS out of 5
  const c=k.calls;
  if(c){
    const word={ok:"good",warn:"fair",bad:"poor"}[c.level];
    put("calls",c.level,c.mos==null?"not measured":`${word} · ${c.mos.toFixed(1)} of 5`,null,
      "How a voice or video call would sound now (a MOS: 4 and up is good), from the last 5 minutes of pings to the internet",c.why);
    $("#kp-calls-note").textContent=c.jitter_ms!=null?`${c.jitter_ms} ms jitter`:"";
    spark($("#kp-calls-spark"),[c.series.map(p=>p[1])],[CC.teal],4.5,{keep:120});
  }
  const r=k.router, temps=r.series.map(p=>p[1]);
  if(r.available){
    const up=r.uptime_s==null?null:r.uptime_s+(k.now-r.ts);  // uptime as of now, not the reading
    put("router",r.level,[r.temp_c==null?null:`${Math.round(r.temp_c)} °C`,up==null?null:`up ${fmtSpan(up)}`].filter(Boolean).join(" · ")||"–",null,
      `CPU temperature ${r.temp_c??"–"} °C (amber from ${r.warn_c} °C, red from ${r.bad_c} °C) · load ${r.load1??"–"} · memory in use ${pc(r.mem_used_pct)}`,r.why);
  } else put("router",null,r.ts?`not read for ${ago(r.ts).replace(" ago","")}`:"not read",null,
    "Hearth reads the router's health along with its traffic: it needs a GL.iNet router and the password file");
  $("#kp-router-note").textContent=temps.length?`day peak ${Math.round(Math.max(...temps))} °C`:"";
  spark($("#kp-router-spark"),[temps],[CC.orange],1,{keep:144,zoom:true});

  const i=k.internet;
  put("inet",i.level,i.up===false?"down":i.measured===false?"not measured":`${pc(i.loss_pct)} lost · ${ms(i.p95_ms)}`,
    i.up===false?"no answers from the internet":i.measured===false?"no pings in the last few seconds":`slowest 5% of pings (typical ${ms(i.p50_ms)}) · ${i.spikes_1h??0} spike${i.spikes_1h===1?"":"s"} in the hour${i.spikes_usual_per_hour!=null?` (usually ${Math.round(i.spikes_usual_per_hour)})`:""}`,
    "Lost pings over the last 5 minutes, and how slow the slowest 5% were over the last minute. Amber or red when either is well above normal",i.why);

  put("today",null,k.today?`↓ ${k.today.down_gb} GB · ↑ ${k.today.up_gb} GB`:"–",k.today?"since midnight, through the router":"needs the router");

  const m=k.mesh;
  if(!m.available) put("mesh",null,"–","mesh system not read");
  else if(!m.satellites) put("mesh",null,"no satellites","one mesh unit");
  else put("mesh",m.level,m.backhaul==="offline"?`${m.name} offline`:m.backhaul==="wired"?`${m.name} · cable`:`${m.name} · ${m.rssi??"–"} dBm`,
    m.backhaul==="wireless"&&m.band?`${BAND[m.band]||m.band} · ${rate(m.rate_rx)} · weakest of ${m.satellites}`:`weakest of ${m.satellites}`,null,m.why);

  const w=k.wifi;
  if(!w.available) put("wifi",null,"–","mesh system not read");
  else put("wifi",w.level,`${w.total} on WiFi${w.poor.length?` · ${w.poor.length} poor`:""}`,
    w.poor.length?"poor: "+w.poor.map(p=>p.name).join(", "):w.fair?`${w.fair} fair, the rest good`:"all connected well",
    w.poor.length?w.poor.map(p=>`${p.name}: ${p.why||""}`).join("\n"):null,w.why);
}

// no data between two buckets (the target wasn't pinged: asleep, away, Hearth stopped) is a
// break in the line, never the last value held across it - a stepped loss line would otherwise
// draw hours of "100% lost" from one reading
const GAP=Symbol("gap");
function withGaps(points,bucket){
  const out=[];
  points.forEach((p,i)=>{ if(i&&bucket&&p[0]-points[i-1][0]>bucket*1.5) out.push([points[i-1][0]+bucket,GAP]); out.push(p) });
  return out;
}
function renderLatency(sum,ser){
  const names=sum.chart;
  const ds=key=>names.map((c,i)=>({label:c.label,data:withGaps(ser.series[c.id]||[],ser.bucket_s).map(p=>({x:p[0],y:p==null||p[1]===GAP?null:key==="lat"?p[2]:p[3]*100})),
      borderColor:COLORS[i%COLORS.length],backgroundColor:COLORS[i%COLORS.length]+"40",borderWidth:1.3,pointRadius:0,spanGaps:false,
      fill:key==="loss"?"origin":false,stepped:key==="loss"}));
  const xs={type:"linear",min:sum.now-minutes*60,max:sum.now,ticks:{color:CC.muted,maxTicksLimit:8,callback:v=>fmtT(v)},grid:{color:CC.grid}};
  const opts=(ylabel,log)=>({animation:false,maintainAspectRatio:false,parsing:false,normalized:true,interaction:{mode:"nearest",axis:"x",intersect:false},
    plugins:{legend:{labels:{color:CC.text,boxWidth:12}},tooltip:{callbacks:{title:it=>fmtT(it[0].parsed.x),label:c=>`${c.dataset.label}: ${c.parsed.y==null?"–":c.parsed.y.toFixed(1)} ${ylabel}`}}},
    scales:{x:xs,y:{type:log?"logarithmic":"linear",min:log?0.5:0,ticks:{color:CC.muted},grid:{color:CC.grid},title:{display:true,text:ylabel,color:CC.muted}}}});
  const log=$("#logscale").checked, lossOpts={...opts("% lost",false),plugins:{legend:{display:false}}};
  if(!latChart){ latChart=new Chart($("#lat"),{type:"line",data:{datasets:ds("lat")},options:opts("ms",log)});
                 lossChart=new Chart($("#loss"),{type:"line",data:{datasets:ds("loss")},options:lossOpts}); }
  else { latChart.data.datasets=ds("lat"); latChart.options=opts("ms",log); latChart.update();
         lossChart.data.datasets=ds("loss"); lossChart.options=lossOpts; lossChart.update(); }
}

const span=s=>s>=120?`${Math.round(s/60)} min`:`${s}s`;   // an episode's length
function renderIncidents(inc){
  const eps=inc.episodes||[], usual=inc.spikes_usual_per_hour;
  // long ranges: older episodes come from saved history, which the server says is complete or not
  $("#inccount").textContent=(inc.episode_breakdown?`(${inc.episode_breakdown})`:"")
    +(inc.history_complete===false&&inc.history_error?` · ${inc.history_error}`:"");
  const listed=(inc.momentary||[]).length, total=inc.spikes_total||0;
  const since=inc.incidents_since?`; listed from ${new Date(inc.incidents_since*1000).toLocaleString()}`:"";
  $("#blipcount").textContent=`(${total}${usual!=null?`, usually ${Math.round(usual)} an hour`:""}${listed<total?`; newest ${listed} listed`:""}${since})`;
  // a truncated episode began before the data it was built from: its start is "earliest seen"
  // opened from the Overview's timeline (at=): the episodes in that 15 minutes are highlighted
  const m=atShown(), inSlot=e=>m!=null&&e.start<m+900&&e.end>=m;
  const epRows=eps.map(e=>`<tr${inSlot(e)?' class="at"':""}><td><a class="itemlink" data-key="ep:${Math.trunc(e.start)}" href="${esc(hashFor("history",rangeLabel(),at,"ep:"+Math.trunc(e.start)))}">${e.truncated?"before ":""}${new Date(e.start*1000).toLocaleString()}</a></td><td>${span(e.duration_s)}</td>
    <td><span class="tag ${e.level}">${esc(e.cause)}</span>${(e.context||[]).map(c=>`<div class="muted small">${esc(c)}</div>`).join("")}</td>
    <td class="small">${e.clusters} burst${e.clusters===1?"":"s"}${e.lost_s?`, ${e.lost_s} s lost`:""}</td></tr>`);
  // exactly the momentary spikes counted next to the tickbox (not the bursts inside episodes)
  const spikeRows=$("#showblips").checked?(inc.momentary||[]).map(r=>
    `<tr class="muted"><td>${new Date(r.start*1000).toLocaleString()}</td><td>${r.duration_s}s</td>
    <td>${esc(r.verdict)}</td><td>${Object.entries(r.targets).map(([n,v])=>`${esc(n)}: ${v.lost?v.lost+" lost":""}${v.lost&&v.max?", ":""}${v.max?"max "+Math.round(v.max)+" ms":""}`).join("<br>")}</td></tr>`):[];
  $("#inc tbody").innerHTML=[...epRows,...spikeRows].join("")
    || `<tr><td colspan="4" class="muted">No slowdowns or outages in this window.</td></tr>`;
  if(m!=null&&!atScrolled){
    const row=$("#inc tbody tr.at");
    if(row){ row.scrollIntoView({block:"center"}); atScrolled=true }
  }
}

function renderDevices(sum,use,dev,tree){
  const stat=Object.fromEntries(sum.devices.map(d=>[d.id,d]));
  const nowBy=Object.fromEntries((use.current?.devices||[]).map(d=>[d.id,d]));
  const usedBy=Object.fromEntries((use.window?.devices||[]).map(d=>[d.id,d]));
  const info=devInfo(dev);
  const ids=[...new Set([...dev.map(d=>d.id),...Object.keys(usedBy),...Object.keys(nowBy)])];
  const total=id=>(usedBy[id]?.down_bytes||0)+(usedBy[id]?.up_bytes||0);
  ids.sort((a,b)=>total(b)-total(a)||(info[b]?.online|0)-(info[a]?.online|0)||String(info[a]?.name||a).localeCompare(info[b]?.name||b));
  $("#usedhead").textContent=`Used (${rangeLabel()})`;
  const asleep=dev.filter(d=>d.state==="asleep").length;
  $("#devcount").textContent=`${dev.filter(d=>d.online).length-asleep} online${asleep?`, ${asleep} asleep`:""} of ${dev.length} seen`;
  // the unit list follows the data; rebuilt only when it changes, so an open list isn't reset
  const units=[...new Set(Object.values(tree.unitOf||{}).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
  const sel=$("#devunit"), key=units.join("\n");
  if(sel.dataset.key!==key){ const was=sel.value;
    sel.innerHTML=`<option value="">Any unit</option>`+units.map(u=>`<option value="${esc(u)}">${esc(u)}</option>`).join("");
    sel.value=units.includes(was)?was:""; sel.dataset.key=key }
  const nameOf=id=>stat[id]?.name||info[id]?.name||usedBy[id]?.name||nowBy[id]?.name||id;
  const shown=ids.filter(id=>devMatches({id,name:nameOf(id),info:info[id]||{},area:tree.areaOf[id],unit:tree.unitOf?.[id],
                                        link:tree.linkOf?.[id],me:id===use.self_id},devFilter()));
  $("#devshown").textContent=shown.length<ids.length?`${shown.length} of ${ids.length} shown`:"";
  // redrawn every refresh: keep keyboard focus on the same device's link (as the map does)
  const hadFocus=document.activeElement?.matches?.("#dev a.itemlink")?document.activeElement.dataset.key:null;
  $("#dev tbody").innerHTML=shown.map(id=>{const s=stat[id], i=info[id]||{}, n=nowBy[id], u=usedBy[id];
    const name=nameOf(id), me=id===use.self_id;
    return `<tr><td><a class="itemlink" data-key="${esc(id)}" href="${esc(hashFor("devices",rangeLabel(),null,id))}">${esc(name)}</a>${me?' <span class="tag">this computer</span>':renameBtn(id,name)}<div class="muted small">${esc([i.ip,i.model||i.vendor].filter(Boolean).join(" · "))}</div></td>
      <td>${esc(tree.areaOf[id]||"")}</td><td class="num">${ms(s?.p50)}</td><td class="num"><span class="tag ${s?lvl(s):""}" title="${esc(s?.why||"")}">${ms(s?.p95)}</span></td><td class="num">${pc(s?.loss_pct)}</td>
      <td class="num">${n?`${mbps(n.down_mbps)} / ${mbps(n.up_mbps)}`:"–"}</td><td class="num">${u?`${fmtB(u.down_bytes)} / ${fmtB(u.up_bytes)}`:"–"}</td>
      <td>${me?"now":i.state==="asleep"?`<span class="dot asleep" title="On the network but not answering - usually asleep"></span>asleep`
        :i.last_seen?`<span class="dot ${i.online?LV.ok:""}"></span>${ago(i.last_seen)}`:"–"}</td></tr>`}).join("")
    ||`<tr><td colspan="8" class="muted">${ids.length?"No devices match these filters.":"First scan runs at startup…"}</td></tr>`;
  if(hadFocus) [...document.querySelectorAll("#dev a.itemlink")].find(a=>a.dataset.key===hadFocus)?.focus({preventScroll:true});
}

// Devices filters: read from the inputs each time, so a refresh keeps them; never sent anywhere
const devFilter=()=>({q:$("#devq").value.trim().toLowerCase(),state:$("#devstate").value,
                      link:$("#devlink").value,unit:$("#devunit").value});
function devMatches(d,f){
  if(f.q&&![d.name,d.id,d.info.ip,d.info.model,d.info.vendor,d.area].some(v=>String(v||"").toLowerCase().includes(f.q))) return false;
  const online=d.me||!!d.info.online;   // asleep counts as online: it's on the network
  if(f.state==="on"&&!online||f.state==="off"&&online) return false;
  if(f.link&&d.link!==f.link) return false;   // unknown link (timing layout) only matches "either"
  if(f.unit&&d.unit!==f.unit) return false;
  return true;
}
let lastDevices=null;   // the last data drawn, so typing redraws at once instead of waiting for a refresh
for(const el of ["#devq","#devstate","#devlink","#devunit"])
  $(el).addEventListener("input",()=>{ if(lastDevices) renderDevices(...lastDevices) });

function renderWifi(wifi){
  // one radio often carries several networks (your WiFi plus a hidden one, which mesh systems
  // typically use between their units): show each radio once, listing what it carries
  const radios={};
  for(const w of wifi){
    const r=radios[`${w.name}|${w.band}|${w.channel}`] ||= {...w,ssids:new Set(),hidden:false};
    if(w.ssid) r.ssids.add(w.ssid); else r.hidden=true;
    if(w.ts>r.ts) Object.assign(r,{ts:w.ts,signal:w.signal,util:w.util,stations:w.stations});
  }
  const carries=r=>[...r.ssids].join(", ")+(r.hidden?(r.ssids.size?" + ":"")+"a hidden network"+(r.ours?" (likely the mesh's own link)":""):"");
  $("#wifi tbody").innerHTML=Object.values(radios).map(w=>`<tr><td>${esc(w.name)}${w.ours?"":' <span class="tag">neighbour</span>'}<div class="muted small">${esc(carries(w))}</div></td><td>${esc(w.band||"")}</td><td class="num">${w.channel??"–"}</td>
    <td class="num">${pc(w.signal)}</td><td class="num"><span class="tag ${w.util==null?"":lvl(w)}" title="${esc(w.why||"")}">${pc(w.util)}</span></td><td class="num">${w.stations??"–"}</td><td>${ago(w.ts)}</td></tr>`).join("")
    ||`<tr><td colspan="7" class="muted">No WiFi scan yet. Scanning currently works when Hearth runs on Windows with a WiFi adapter switched on.</td></tr>`;
}

// optional parts never blank the rest: each falls back to "not available"
const FALLBACK={usage:{available:false},mesh:{available:false},host:{available:false},kpi:null,overview:null};
async function refresh(){
  if(editing) return;  // don't wipe a name being typed
  const shown=tab, own=["status",...TAB_FETCH[shown]];
  // an open side panel needs the map's data on any tab; fetched here if the tab doesn't, and a
  // failure there only affects the panel, never the tab
  const kind=itemKind(item), extra=item&&kind==="map"?MAP_DATA.filter(n=>!own.includes(n)):[], PANEL_FAILED={};
  // an episode: its incidents over the smallest range that still holds it, unless the History
  // tab already loads at least that much (so an older episode is never judged missing)
  const epWindow=kind==="ep"?rangeFor(+item.slice(3))[1]:null;
  const epOwn=kind==="ep"&&shown==="history"&&minutes>=epWindow;
  const epFetch=kind==="ep"&&!epOwn?fetch(`/api/incidents?minutes=${epWindow}`).then(r=>r.ok?r.json():PANEL_FAILED).catch(()=>PANEL_FAILED):null;
  const alertsFetch=kind==="alerts"?fetch("/api/alerts").then(r=>r.ok?r.json():PANEL_FAILED).catch(()=>PANEL_FAILED):null;
  // a failed fetch of the panel's data marks the panel failed even where the tab falls back
  // (usage, mesh): a fallback must never make a valid item look "not found"
  let mapFailed=false;
  const fetchOne=n=>get("/api/"+n).catch(e=>{ if(MAP_DATA.includes(n)) mapFailed=true;
    if(n in FALLBACK) return FALLBACK[n]; if(own.includes(n)) throw e; return PANEL_FAILED });
  let got;
  try{ got=await Promise.all([...[...own,...extra].map(fetchOne),epFetch,alertsFetch]) }
  catch(e){ if(shown===tab&&item) renderPanel(null,true); throw e }
  if(shown!==tab) return;  // the tab changed while this was loading: its own refresh draws it
  const names=[...own,...extra], d=Object.fromEntries(names.map((n,i)=>[n,got[i]]));
  const epData=epOwn?d.incidents:got[names.length], alertsData=got[names.length+1];
  lastStatus=d.status; renderStatus(d.status); renderBanner(d.status); renderAlertCount(d.status);
  if(shown==="overview"){ renderWelcome(d.status); renderKpi(d.kpi); renderOverview(d.kpi,d.overview); renderDigest(d.digest?.digest) }
  // a unit: item lives in the mesh reading: without one (a failed read) it can't be judged missing
  // each kind fails on its own data only
  const panelFailed=kind==="ep"?epData===PANEL_FAILED||!epData
    :kind==="alerts"?alertsData===PANEL_FAILED||!alertsData
    :kind==="src"?false
    :mapFailed||names.some(n=>d[n]===PANEL_FAILED)||(item?.startsWith("unit:")&&d.mesh&&!d.mesh.available);
  let tree=null;
  if([d.summary,d.devices,d.usage,d.mesh].every(x=>x&&x!==PANEL_FAILED)){
    const {summary:sum,usage:use,devices:dev,mesh}=d;
    last={sum,use};
    tree=indexTree(mesh.available&&mesh.nodes.length?buildMeshTree(sum,use,dev,mesh):buildTree(sum,use,dev),sum,use,dev);
    if(d.kpi?.internet) tree.root.health=lvl(d.kpi.internet);  // the same judgement as the header and the tile
    if(d.kpi) routerLink=d.kpi.router?.link||null;             // the router's panel: its connection and shaping
    latestTree=tree;
  }
  if(tree&&(shown==="network"||shown==="devices")){
    const {summary:sum,usage:use,devices:dev,mesh}=d;
    if(shown==="network"){
      $("#mapnote").textContent=tree.fromMesh?`layout from your mesh system, read ${ago(mesh.ts)} · colours from Hearth's pings · click anything for detail`
        :mesh.stale_since?`mesh system last read ${ago(mesh.stale_since)}${mesh.error?` (${mesh.error.error})`:""} · showing the layout worked out from timing`
        :sum.layout_known?"layout worked out from timing · click anything for detail":"still learning the layout (about 5 minutes)";
      renderMap(tree); renderMesh(mesh); renderTrust(mesh); renderWifi(d.wifi);
    } else { lastDevices=[sum,use,dev,tree]; renderDevices(...lastDevices) }
  }
  if(shown==="history"){
    renderLatency(d.summary,d.series); renderIncidents(d.incidents); renderQuality(d.quality);
    $("#ev tbody").innerHTML=d.events.map(e=>`<tr><td>${new Date(e.ts*1000).toLocaleString()}</td><td>${esc(e.detail)}</td></tr>`).join("")||`<tr><td colspan="2" class="muted">No events.</td></tr>`;
  }
  if(shown==="history") renderReports();   // its own fetches, with their own parameters
  if(shown==="usage"){ renderTraffic(d.usage); renderUsageMonth(); renderSpeedtest(d.speedtest) }
  if(shown==="system"){ renderSecurity(d.security); renderSetup(d.setup); renderHost(d.host); renderSources(d.status); renderDns(d.dns); renderSettings(d.settings) }
  renderPanel(panelFailed?null:{tree:tree??undefined,eps:epData?.episodes,sources:d.status?.sources,alerts:alertsData},panelFailed);
}

// ---------------------------------------------------------------- outages and the report card
// (step 4.1) real outages over weeks or months, and a month's ISP report card; both fetched with
// their own parameters (a fixed set of days, a month from the list), never anything typed
const SIDE_WORD={isp:"Your ISP or beyond",home:"Your home network",unclear:"Unclear (router not measured)"};
const WEEKDAY=["Mondays","Tuesdays","Wednesdays","Thursdays","Fridays","Saturdays","Sundays"];
// a month picker: the server's current month and the 13 before (its clock decides what "this
// month" is, so a browser in another timezone never offers one the server calls the future).
// Rebuilt when the server's current month moves on, so a page left open keeps up; the choice is kept
function fillMonths(sel,current){
  if(!/^\d{4}-\d{2}$/.test(current||"")||sel.dataset.current===current) return;
  const keep=sel.value; sel.innerHTML="";
  let [y,m]=current.split("-").map(Number);
  for(let i=0;i<=13;i++){
    sel.add(new Option(new Date(y,m-1,1).toLocaleDateString([], {month:"long",year:"numeric"}),`${y}-${String(m).padStart(2,"0")}`));
    if(--m===0){ m=12; y-- }
  }
  if([...sel.options].some(o=>o.value===keep)) sel.value=keep;
  sel.dataset.current=current;
}
// one fetch at a time; a change (a picker, or a refresh) arriving meanwhile runs once more after it,
// so the panels always end up showing what the pickers say
let reportsBusy=false, reportsAgain=false;
async function renderReports(){
  if(reportsBusy){ reportsAgain=true; return }
  reportsBusy=true; reportsAgain=false;
  const days=$("#outdays").value, month=$("#repmonth").value;
  try{
    const [o,r]=await Promise.all([get(`/api/outages?days=${encodeURIComponent(days)}`).catch(()=>null),
                                   get(month?`/api/report?month=${encodeURIComponent(month)}`:"/api/report").catch(()=>null)]);
    if(r) fillMonths($("#repmonth"),r.this_month);
    renderOutages(o); renderReport(r);
  } finally { reportsBusy=false; if(reportsAgain) renderReports() }
}
function renderOutages(o){
  if(!o){ $("#outsum").textContent="couldn't load"; return }
  const t=o.totals, n=Object.values(t).reduce((a,x)=>a+x.count,0);
  $("#outsum").innerHTML=`<span class="dot ${LV[o.uptime.level]??""}"></span>${o.uptime_pct==null?"not measured yet":
    `up ${o.uptime_pct.toFixed(2)}% of the time Hearth was measuring`} · ${n} outage${n===1?"":"s"}`+
    (n?` (${t.outage.count} your ISP, ${t.home_down.count} home, ${t.internet_down.count} unclear)`:"");
  $("#outages tbody").innerHTML=o.outages.map(e=>`<tr><td><a class="itemlink" data-key="ep:${Math.trunc(e.start)}" href="${esc(hashFor("history",rangeLabel(),at,"ep:"+Math.trunc(e.start)))}">${e.truncated?"before ":""}${esc(new Date(e.start*1000).toLocaleString())}</a></td>
    <td>${esc(span(Math.round(e.end-e.start)))}</td><td>${esc(SIDE_WORD[e.side]||"")}</td><td>${esc(e.cause||"")}</td></tr>`).join("")
    +(o.limited?`<tr><td colspan="4" class="muted">Only the newest ${o.outages.length} are listed; the totals cover them all.</td></tr>`:"")
    ||`<tr><td colspan="4" class="muted">No outages in the last ${o.days} days.</td></tr>`;
}
function renderReport(r){
  const box=$("#report");
  if(!r){ box.textContent="Couldn't load the report card."; return }
  const o=r.outages, l=r.latency, w=r.worst_hour, mins=m=>m<1?"under a minute":`${Math.round(m)} min`;
  box.className="";
  box.innerHTML=(r.partial?`<p class="muted small">Hearth measured ${Math.round(r.coverage*100)}% of this month, so this card is partial.</p>`:"")+
    `<dl class="kv"><dt>Uptime</dt><dd><span class="dot ${LV[r.uptime.level]??""}"></span>${r.uptime_pct==null?"not measured":r.uptime_pct.toFixed(2)+"%"}</dd>
    <dt>Outages: your ISP</dt><dd>${o.isp.count}${o.isp.count?` · ${esc(mins(o.isp.minutes))}`:""}</dd>
    <dt>Outages: your home</dt><dd>${o.home.count}${o.home.count?` · ${esc(mins(o.home.minutes))}`:""}</dd>
    ${o.unclear.count?`<dt>Outages: unclear</dt><dd>${o.unclear.count} · ${esc(mins(o.unclear.minutes))}</dd>`:""}
    <dt>Slowdowns and problems</dt><dd>${r.slow.count}${r.slow.count?` · ${esc(mins(r.slow.minutes))}, ${r.slow.on_line} on the broadband line or beyond`:""}</dd>
    <dt>Latency to the internet</dt><dd><span class="dot ${LV[l.level]??""}"></span>${ms(l.p50_ms)} typical · ${ms(l.p95_ms)} slowest 5% · ${pc(l.loss_pct)} lost</dd>
    <dt>Worst hour of the week</dt><dd>${w?`${WEEKDAY[w.weekday]} ${String(w.hour).padStart(2,"0")}:00 (${ms(w.median_ms)} typical)`:"not enough data yet"}</dd></dl>`;
}
for(const el of ["#outdays","#repmonth"]) $(el).addEventListener("change",()=>renderReports());

// ---------------------------------------------------------------- calls and DNS over time (#101)
let qualityDrawn=null;
function renderQuality(q){
  if(!q) return;
  // redrawn only when the data (or the theme's colours) changed, not on every refresh
  const key=JSON.stringify([q.mos,q.dns,q.now/60|0,minutes,CC]); if(key===qualityDrawn) return; qualityDrawn=key;
  const pts=(series,bucket)=>withGaps(series,bucket).map(p=>({x:p[0],y:p[1]===GAP?null:p[1]}));
  const xs={type:"linear",min:q.now-minutes*60,max:q.now,ticks:{color:CC.muted,maxTicksLimit:8,callback:v=>fmtT(v)},grid:{color:CC.grid}};
  const opts=(y,label)=>({animation:false,maintainAspectRatio:false,parsing:false,interaction:{mode:"nearest",axis:"x",intersect:false},
    plugins:{legend:{labels:{color:CC.text,boxWidth:12}},tooltip:{callbacks:{title:it=>fmtT(it[0].parsed.x),label:c=>`${c.dataset.label}: ${c.parsed.y==null?"–":c.parsed.y}${label}`}}},
    scales:{x:xs,y:{...y,ticks:{color:CC.muted},grid:{color:CC.grid}}}});
  const mos=[{label:"Call rating",data:pts(q.mos,q.bucket_s),borderColor:CC.teal,borderWidth:1.3,pointRadius:0,spanGaps:false}];
  const dns=q.dns.map((r,i)=>({label:r.name,data:pts(r.points,q.bucket_s),borderColor:[CC.blue,CC.purple,CC.orange][i%3],borderWidth:1.3,pointRadius:0,spanGaps:false}));
  if(qMosChart) qMosChart.destroy();
  if(qDnsChart) qDnsChart.destroy();
  qMosChart=new Chart($("#qmos"),{type:"line",data:{datasets:mos},options:opts({min:1,max:4.5,title:{display:true,text:"rating",color:CC.muted}},"")});
  qDnsChart=new Chart($("#qdns"),{type:"line",data:{datasets:dns},options:opts({beginAtZero:true,title:{display:true,text:"ms",color:CC.muted}}," ms")});
}

// ---------------------------------------------------------------- first-run welcome (step 5.3)
// shown while Hearth is new: started in the last 10 minutes, or the layout isn't learned yet;
// "Got it" hides it for good in this browser
// shown for 10 minutes, or up to 30 while the layout isn't known yet: a home where it never is
// (too few devices to time) mustn't keep the card for good
const WELCOME_KEY="hearth_welcome_done", WELCOME_S=600, WELCOME_MAX_S=1800;
let welcomeClosed=false;   // "Got it" holds for this page even when storage is blocked
let welcomeHtml="";        // the text last written
function renderWelcome(st){
  let done=welcomeClosed; try{ done=done||localStorage.getItem(WELCOME_KEY)==="1" }catch(e){}
  const age=st?st.updated-st.started:0;
  const fresh=st&&(age<WELCOME_S||(!st.layout_known&&age<WELCOME_MAX_S));
  $("#welcome").hidden=done||!fresh;
  if($("#welcome").hidden) return;
  const mins=Math.max(1,Math.round(age/60));
  const layout=st.layout_known?"has worked out the layout":age<WELCOME_S?"works out the layout over about 5 minutes":"is still working out the layout";
  const html=`Hearth started ${mins} minute${mins===1?"":"s"} ago and is getting to know your network.
    It pings your router, the internet and every device it finds, and ${layout} -
    the map, the timeline and "Needs attention" fill in as it goes. To read your router or mesh too, see
    <a href="${esc(hashFor("system",rangeLabel()))}">System, Setup</a>.`;
  // only when it changed: rewriting it every poll drops a selection and the link's focus (#112)
  if(html!==welcomeHtml){ welcomeHtml=html; $("#welcometext").innerHTML=html }
}
$("#welcomeclose").addEventListener("click",()=>{ welcomeClosed=true; save(WELCOME_KEY,"1"); $("#welcome").hidden=true });

// ---------------------------------------------------------------- weekly digest (step 4.7)
function renderDigest(w){
  if(!w) return;   // the "not built yet" text stays
  const day=t=>new Date(t*1000).toLocaleDateString([], {day:"numeric",month:"short"});
  $("#ov-week-dates").textContent=`${day(w.week_start)} – ${day(w.week_end-43200)}`;
  const u=w.usage, st=w.speedtests;
  const rows=[
    ["Uptime",w.uptime_pct==null?"not measured":`${w.uptime_pct.toFixed(2)}% · ${w.outages} outage${w.outages===1?"":"s"}${w.outages?` (${Math.round(w.outage_minutes)} min)`:""}`],
    ["Slow spells",`${w.slow_spells}${w.slowest_day?` · worst on ${w.slowest_day.day} (${Math.round(w.slowest_day.minutes)} min)`:""}`],
    ["Typical latency",ms(w.latency_ms)],
    ["Used",u.source?`↓ ${u.down_gb} GB · ↑ ${u.up_gb} GB${u.top?` · most: ${u.top.name} (${u.top.gb} GB)`:""}`:"not read"],
    ["New devices",w.new_devices.length?w.new_devices.join("; "):"none"],
    ["Alerts",String(w.alerts)],
    ["Speed tests",st.count?`${st.count} · last ${mbps(st.last.down)} down, ${mbps(st.last.up)} up, grade ${st.last.grade||"–"}`:"none"]];
  const box=$("#ov-week"); box.className="";
  box.innerHTML=`<p style="margin:0 0 8px"><b>${esc(w.headline)}</b></p><dl class="kv">${rows.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
}

// ---------------------------------------------------------------- speed test (step 4.6)
// started only by the button (or a schedule set in config.json); while one runs, the panel
// checks every 1.5 s so the phase and the result show without waiting for the page's refresh
let stPolling=null;
function renderSpeedtest(s){
  if(!s){ $("#stnote").textContent="couldn't load"; return }
  const PH={starting:"Starting…",download:"Testing download…",upload:"Testing upload…"};
  $("#stnote").textContent=s.running?PH[s.phase]||"Running…":s.error?`The last test failed: ${s.error}`:"";
  $("#strun").disabled=s.running||!s.server;
  $("#stabout").textContent=!s.server?`Speed tests can't run: ${s.server_problem||"no server set"} (speedtest_server in config.json).`:
    `Sends test data to ${s.server} for about 20 seconds; your internet will be busy meanwhile.`+
    (s.schedule&&s.schedule!=="off"?` Also runs ${s.schedule} (set in config.json).`:"")+
    // a test can't measure past the router's shaping: say so, or a result at the cap reads as the line's speed
    (s.shaping?.enabled&&s.shaping.down_mbps!=null?` Your router shapes traffic to ${shapingText(s.shaping)} so a busy line `+
      `stays responsive: results can't go above that.`:"");
  const when=t=>new Date(t*1000).toLocaleString();
  $("#speedtests tbody").innerHTML=s.results.map(r=>r.error?`<tr><td>${esc(when(r.ts))}</td><td colspan="5" class="muted">Failed: ${esc(r.error)}</td></tr>`
    :`<tr><td>${esc(when(r.ts))}</td><td class="num">${esc(mbps(r.down))}</td><td class="num">${esc(mbps(r.up))}</td>
      <td><span class="dot ${LV[r.level]??""}"></span>${r.grade?`${esc(r.grade)} · +${Math.round(r.rise_ms)} ms`:"–"}</td>
      <td class="num">${esc(ms(r.idle_ms))}</td><td class="num">${esc(ms(r.loaded_down_ms))} / ${esc(ms(r.loaded_up_ms))}</td></tr>`).join("")
    ||`<tr><td colspan="6" class="muted">No speed tests yet.</td></tr>`;
  if(s.running&&!stPolling) stPolling=setInterval(async()=>{
    const n=await get("/api/speedtest").catch(()=>null);
    if(n) renderSpeedtest(n);
    if(!n||!n.running){ clearInterval(stPolling); stPolling=null }
  },1500);
}
$("#strun").addEventListener("click",async()=>{
  $("#strun").disabled=true; $("#stnote").textContent="Starting…";
  try{
    const r=await fetch("/api/speedtest",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
    if(!r.ok){ const d=await r.json().catch(()=>({})); $("#stnote").textContent=d.error||"Couldn't start the test."; $("#strun").disabled=false; return }
  }catch(e){ $("#stnote").textContent="Hearth didn't answer."; $("#strun").disabled=false; return }
  const n=await get("/api/speedtest").catch(()=>null); if(n) renderSpeedtest(n);
});

// ---------------------------------------------------------------- usage month (step 4.2)
// the answer names the current usage month (it turns on the start day); the picker lists it and 13 before
let usageBusy=false, usageAgain=false, usageDrawn=null;
async function renderUsageMonth(){
  if(usageBusy){ usageAgain=true; return }
  usageBusy=true; usageAgain=false;
  const month=$("#usemonth").value;
  try{
    const u=await get(month?`/api/usage/month?month=${encodeURIComponent(month)}`:"/api/usage/month").catch(()=>null);
    if(u) fillMonths($("#usemonth"),u.current);
    drawUsageMonth(u);
  } finally { usageBusy=false; if(usageAgain) renderUsageMonth() }
}
function drawUsageMonth(u){
  const sum=$("#usemonthsum");
  if(!u){   // nothing from another month left on screen under this message
    sum.textContent="Couldn't load this month's usage."; $("#usedevs tbody").innerHTML="";
    if(usageDaysChart){ usageDaysChart.destroy(); usageDaysChart=null } usageDrawn=null; return }
  // the data changes at most hourly: redraw only when it (or the theme's colours) changed
  const key=JSON.stringify([u,CC]); if(key===usageDrawn) return; usageDrawn=key;
  const day=d=>new Date(d*1000).toLocaleDateString([], {day:"numeric",month:"short"});
  const total=u.down+u.up, prev=u.previous&&(u.previous.down+u.previous.up);
  sum.innerHTML=!u.source?"Hearth has no usage for this month: it needs the router's traffic readings (or UPnP).":
    `<b>↓ ${esc(fmtB(u.down))} · ↑ ${esc(fmtB(u.up))}</b> from ${esc(day(u.since))} to ${esc(day(u.complete?u.end:u.until))}${u.complete?"":" (so far)"}`+
    (prev?` · the month before: ${esc(fmtB(prev))}`:"")+(u.starts_day!==1?` · months start on day ${u.starts_day|0}`:"")+
    (u.source==="wan"?` · <span class="muted">totals from the router's own counters; no per-device split</span>`:"");
  const ds=[{label:"Down",data:u.days.map(d=>d.down/1e9),backgroundColor:CC.blue},{label:"Up",data:u.days.map(d=>d.up/1e9),backgroundColor:CC.orange}];
  const labels=u.days.map(d=>new Date(d.date+"T12:00").toLocaleDateString([], {day:"numeric",month:"short"}));
  if(usageDaysChart) usageDaysChart.destroy();
  usageDaysChart=new Chart($("#usedays"),{type:"bar",data:{labels,datasets:ds},options:{animation:false,maintainAspectRatio:false,
    plugins:{legend:{labels:{color:CC.text,boxWidth:12}},tooltip:{callbacks:{label:x=>`${x.dataset.label}: ${x.parsed.y.toFixed(2)} GB`}}},
    scales:{x:{stacked:true,ticks:{color:CC.muted,maxTicksLimit:12},grid:{display:false}},
            y:{stacked:true,beginAtZero:true,ticks:{color:CC.muted},grid:{color:CC.grid},title:{display:true,text:"GB",color:CC.muted}}}}});
  $("#usedevs tbody").innerHTML=u.devices.map(d=>`<tr><td>${esc(d.name)}</td><td class="num">${esc(fmtB(d.down))}</td><td class="num">${esc(fmtB(d.up))}</td>
    <td class="num">${total?Math.round(100*(d.down+d.up)/total)+"%":"–"}</td></tr>`).join("")
    ||`<tr><td colspan="4" class="muted">${u.source==="wan"?"The router's own counters give totals only.":"No devices used the internet this month."}</td></tr>`;
}
$("#usemonth").addEventListener("change",()=>renderUsageMonth());

// ---------------------------------------------------------------- Overview
// the answer first: the verdict, the last 24 hours, and what needs attention - all decided on
// the server (/api/kpi, /api/overview); the page only draws them
const LEVEL_WORD={ok:"fine",warn:"slow at times",bad:"outage or problem",unknown:"not measured"};
const tabName=t=>TABS.find(x=>x[0]===t)?.[1];
function renderOverview(k,o){
  const v=k?.verdict;
  $("#ov-verdict").innerHTML=v?`<span class="dot ${LV[v.level]??""}"></span>${esc(v.text)}`:"Hearth is still measuring.";
  document.querySelectorAll("#kpis a.tile").forEach(a=>a.href=hashFor(a.dataset.tab,rangeLabel()));
  const when=s=>new Date(s*1000).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
  const slots=o?.timeline||[];
  $("#ov-timeline").innerHTML=slots.length?slots.map(s=>{
    const n=s.episodes.length;
    const what=`${when(s.start)} to ${when(s.start+900)}: ${LEVEL_WORD[s.level]||s.level}`+   // escaped once, below
      (n?` (${n} slowdown${n>1?"s":""} or outage${n>1?"s":""})`:"");
    return `<button class="${LV[s.level]??LV.unknown}" data-at="${Math.trunc(s.start)}" title="${esc(what)}" aria-label="${esc(what)}"></button>`}).join("")
    :`<span class="muted small">${esc(!o?"Hearth couldn't load the last 24 hours.":o.timeline_error||"Not worked out yet.")}</span>`;
  // a block opens History at that moment, its slowdowns highlighted
  $("#ov-timeline").querySelectorAll("button").forEach(b=>b.onclick=()=>go({tab:"history",range:"24h",at:+b.dataset.at}));
  const items=o?.attention||[];
  $("#ov-attention").innerHTML=items.length?items.map(i=>{ const t=tabName(i.tab)?i.tab:"overview";
    return `<li><span class="dot ${LV[i.level]??""}"></span><span>${esc(i.text)}</span> <a href="${esc(hashFor(t,rangeLabel(),null,validItem(i.item)?i.item:null))}">${esc(tabName(t))}</a></li>`}).join("")
    :`<li class="muted">${!o?"Hearth couldn't load this list.":"Nothing needs attention."}</li>`;   // never "nothing" when unknown
}

// something that needs you, whatever tab is open; the details live on their own tab
function renderBanner(st){
  $("#banner").innerHTML=st?.mesh_pending?`<div class="panel" style="border-color:var(--warn)">
    <b>Your mesh needs a confirmation</b> <span class="muted small">Hearth stopped reading it until you decide.</span>
    <a href="${hashFor("network",rangeLabel())}">Open Network</a></div>`:"";
}

// the data sources (router, mesh, UPnP, saved history): set up or not, working or failing, and why
const SOURCE_NAMES={router:"Router",mesh:"Mesh system",upnp:"Router (UPnP)",dns:"DNS check",notify:"Notifications",backup:"Backups",history:"Saved history"};
// ---------------------------------------------------------------- DNS (step 4.3a)
function renderDns(d){
  const rs=d?.resolvers||[];
  $("#dns tbody").innerHTML=rs.map(r=>`<tr><td>${esc(r.name)}${r.name===r.resolver?"":` <span class="muted small">${esc(r.resolver)}</span>`}</td>
    <td><span class="dot ${LV[r.level]??""}"></span>${esc(LV_WORD[LV[r.level]]||"")}</td>
    <td class="num">${ms(r.p50_ms)}</td><td class="num">${ms(r.p95_ms)}</td><td class="num">${pc(r.fail_pct)}</td>
    <td>${r.last?(r.last.rcode===0?`${ms(r.last.ms)} · ${ago(r.last.ts)}`:`<span class="tag bad">${r.last.rcode==null?"no answer":"refused or failed"}</span> ${ago(r.last.ts)}`):"–"}</td></tr>`).join("")
    ||`<tr><td colspan="6" class="muted">${d?"Not checked yet: the first check runs within a minute of starting.":"Couldn't load the DNS check."}</td></tr>`;
}
// ---------------------------------------------------------------- alerts (step 4.4a)
// the header's count: active alerts, and how many you haven't seen; the list is the side panel
function renderAlertCount(st){
  const n=st?.alerts_active|0, unseen=st?.alerts_unseen|0, b=$("#alertsbtn");
  $("#alertcount").textContent=n?String(n):"";
  b.classList.toggle("on",n>0||unseen>0);
  b.setAttribute("aria-label",`Alerts: ${n} active${unseen?`, ${unseen} not seen`:""}`);
}
function renderAlerts(a){
  const when=t=>new Date(t*1000).toLocaleString();
  const row=r=>`<li><span class="dot ${LV[r.level]??""}"></span><span>${esc(r.text)}</span>
    <div class="muted small">${r.kind==="event"?esc(when(r.first)):r.cleared?`${esc(when(r.first))} – cleared ${esc(when(r.cleared))}`:`since ${esc(when(r.first))}`}${r.seen?"":" · new"}
    ${r.tab&&tabName(r.tab)?` · <a href="${esc(hashFor(r.tab,rangeLabel(),null,validItem(r.item)?r.item:null))}">${esc(tabName(r.tab))}</a>`:""}</div></li>`;
  $("#detail").innerHTML=`<h3 id="panel-title">Alerts</h3>`+
    (a.active.length?`<ul class="alertlist">${a.active.map(row).join("")}</ul>`:`<p class="muted small">Nothing needs you right now.</p>`)+
    (a.recent.length?`<h4 class="small muted" style="margin:14px 0 6px">The last 7 days</h4><ul class="alertlist">${a.recent.map(row).join("")}</ul>`:"")+
    (a.unseen?`<p><button class="btn" type="button" id="alertsseen">Mark all seen</button></p>`:"")+
    `<p class="muted small">Turn kinds of alert on or off in System, Settings.</p>`;
  $("#alertsseen")?.addEventListener("click",async()=>{
    try{ await fetch("/api/alerts/seen",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}) }catch(e){}
    refresh().catch(()=>{});
  });
}
$("#alertsbtn").addEventListener("click",()=>{ panelOpener=$("#alertsbtn"); go({item:"alerts"}) });

// ---------------------------------------------------------------- setup checklist (step 5.1)
// #131: each way in from the internet as the server worded it, worst first; then the firmware
function renderSecurity(s){
  if(!s||!Array.isArray(s.items)){ $("#security").innerHTML=`<li class="muted">Couldn't load the security check.</li>`; $("#firmware").textContent=""; return }
  $("#security").innerHTML=s.available?s.items.map(i=>`<li><span class="dot ${LV[i.level]??""}"></span>${esc(i.text)}</li>`).join("")
    :`<li class="muted">Needs the router's password (Setup, below): Hearth reads what's open from the router's own settings.</li>`;
  $("#firmware").textContent=s.firmware?.length?"Firmware: "+s.firmware.map(f=>`${f.what} ${f.version}${f.date?` (${f.date.slice(0,10)})`:""}`).join(" · "):"";
}

function renderSetup(s){
  if(!s){ $("#setup").innerHTML=`<li class="muted">Couldn't load the setup checklist.</li>`; return }
  $("#setup").innerHTML=s.items.map(i=>`<li><span class="dot ${LV[i.level]??""}"></span><b>${esc(i.title)}</b>${i.optional?' <span class="muted small">optional</span>':""}
    <div class="small">${esc(i.text)}</div>${i.action?`<div class="small muted">${esc(i.action)}</div>`:""}</li>`).join("");
  const c=s.credentials;
  // the channels by kind only: their addresses never come back from the server
  const chans=(c.notify||[]).filter(Boolean);
  $("#setup-creds").textContent=`Passwords file: ${s.credentials_file} - router password ${c.router?"set":"not set"}, Deco password ${c.mesh?"set":"not set"}, `+
    `notifications ${chans.length?chans.join(" and "):"not set"}${c.notify_token?" (with a ntfy token)":""}.`+
    (s.local?" You can set them below.":" To set them here, open this page on the computer running Hearth, or edit that file.");
  $("#credsform").hidden=!s.local;    // only on the Hearth computer: the server refuses anywhere else
  $("#notifytest").hidden=!chans.length;
}
// passwords and notification addresses go only to the server, only from the Hearth computer;
// never shown, never refilled. A ticked "remove" sends "" for that line
const CRED_FIELDS=["router","mesh","notify","notify_2","notify_token"], CRED_REMOVABLE=["notify","notify_2","notify_token"];
$("#credsform").addEventListener("submit",async e=>{
  e.preventDefault();
  const body={}, st=$("#cred-status");
  // passwords exactly as typed (the server says if an edge space can't be kept); addresses trimmed
  for(const k of CRED_FIELDS){ const raw=$("#cred-"+k).value, v=k.startsWith("notify")?raw.trim():raw; if(v) body[k]=v }
  for(const k of CRED_REMOVABLE) if($("#rm-"+k).checked) body[k]="";
  if(!Object.keys(body).length){ st.textContent="Type something to save, or tick what to remove."; return }
  st.textContent="Saving…";
  try{
    const res=await fetch("/api/setup/credentials",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await res.json().catch(()=>({}));
    if(!res.ok){ st.textContent=`Not saved: ${d.error||"the server refused it"}`; return }
    for(const k of CRED_FIELDS) $("#cred-"+k).value="";
    for(const k of CRED_REMOVABLE) $("#rm-"+k).checked=false;
    st.textContent="Saved. Hearth will use it within a minute."; renderSetup(d);
  }catch(err){ st.textContent="Not saved: Hearth didn't answer." }
});
// a fixed message to the channels set up (the server allows one a minute)
$("#notifytestbtn").addEventListener("click",async()=>{
  const st=$("#notifytest-status"); st.textContent="Sending…";
  try{
    const res=await fetch("/api/notify/test",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
    const d=await res.json().catch(()=>({}));
    if(!res.ok){ st.textContent=d.error||"Hearth refused it."; return }
    st.textContent=(d.results||[]).map(r=>`${r.kind||"an address"}: ${r.ok?"sent":`failed (${r.error})`}`).join(" · ")||"No notification address is set up.";
  }catch(err){ st.textContent="Hearth didn't answer." }
});

// ---------------------------------------------------------------- settings (step 4.5)
// the form is refilled from the server only while nobody is editing it, so a refresh never wipes
// what's being typed; the server checks every value (settings.py) and says what's wrong
let settingsDirty=false;
function renderSettings(s){
  if(!s||settingsDirty) return;
  const v=s.values;
  $("#set-day").value=v.usage_month_starts??1;
  $("#set-resolvers").value=(v.dns_resolvers||[]).join(", ");
  $("#set-probe").value=v.dns_probe_name||"";
  $("#set-resolvers-hint").textContent=`"gateway" (your router), an address on your network, or ${s.public_resolvers.join(", ")}`;
  $("#set-speedtest").textContent=`${s.read_only.speedtest_schedule||"off"} (set in config.json)`;
  for(const k of ["alert_attention","alert_outages","alert_calls","alert_new_devices"]) $("#set-"+k).checked=!!v[k];
  $("#set-notify_level").value=v.notify_level==="bad"?"bad":"warn";
  $("#set-dashboard_url").value=v.dashboard_url||"";
}
$("#settings").addEventListener("input",()=>{ settingsDirty=true; $("#set-status").textContent="" });
$("#settings").addEventListener("submit",async e=>{
  e.preventDefault();
  const day=$("#set-day").value.trim(), res=$("#set-resolvers").value.split(",").map(x=>x.trim()).filter(Boolean);
  // empty: back to config.json's; a day that isn't a number is sent as typed, so the server says why
  const body={usage_month_starts:day===""?null:/^[0-9]+$/.test(day)?Number(day):day,
              dns_resolvers:res.length?res:null,
              dns_probe_name:$("#set-probe").value.trim()||null,
              alert_attention:$("#set-alert_attention").checked, alert_outages:$("#set-alert_outages").checked,
              alert_calls:$("#set-alert_calls").checked, alert_new_devices:$("#set-alert_new_devices").checked,
              notify_level:$("#set-notify_level").value, dashboard_url:$("#set-dashboard_url").value.trim()||null};
  const st=$("#set-status"); st.textContent="Saving…";
  try{
    const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json().catch(()=>({}));
    if(!r.ok){ st.textContent=`Not saved: ${d.error||"the server refused it"}`; return }
    settingsDirty=false; renderSettings(d); st.textContent="Saved.";
  }catch(err){ st.textContent="Not saved: Hearth didn't answer." }
});

const sourceState=s=>!s.configured?`<span class="dot"></span>not set up`:s.ok===true?`<span class="dot good"></span>working`
  :s.ok===false?`<span class="dot bad"></span>failing${s.since?` since ${esc(ago(s.since))}`:""}`:`<span class="dot"></span>starting`;
const sourceWhy=s=>s.error||s.detail?.why||(s.detail?.host?`at ${s.detail.host}`:"")||(s.last_ok?`last worked ${ago(s.last_ok)}`:"");
function renderSources(st){
  const rows=Object.entries(st?.sources||{}).map(([k,s])=>{
    const link=validItem("src:"+k)?`<a class="itemlink" data-key="${esc("src:"+k)}" href="${esc(hashFor("system",rangeLabel(),null,"src:"+k))}">${esc(SOURCE_NAMES[k]||k)}</a>`:esc(SOURCE_NAMES[k]||k);
    return `<tr><td>${link}</td><td>${sourceState(s)}</td><td class="muted small">${esc(sourceWhy(s))}</td></tr>`});
  $("#sources tbody").innerHTML=rows.join("")||`<tr><td colspan="3" class="muted">No sources have reported yet.</td></tr>`;
}

// inline rename: click ✎, type, Enter saves, Escape cancels
document.addEventListener("click",e=>{
  const b=e.target.closest(".rename"); if(!b) return;
  editing=true;
  const box=document.createElement("input");
  box.className="namebox"; box.maxLength=60; box.value=b.dataset.name; box.setAttribute("aria-label","New name");
  b.replaceWith(box); box.focus(); box.select();
  const done=async ok=>{
    box.onblur=null; editing=false;
    if(ok) await fetch("/api/label",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:b.dataset.key,name:box.value.trim()})});
    refresh();
  };
  box.onkeydown=k=>{ if(k.key==="Enter") done(true); if(k.key==="Escape") done(false) };
  box.onblur=()=>done(false);
});
$("#usagerefresh").onclick=async()=>{
  const b=$("#usagerefresh"); b.disabled=true; b.textContent="Reading router…";
  try{ await fetch("/api/router/refresh",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}) }catch(e){}
  setTimeout(async()=>{ try{ await refresh() }catch(e){} b.disabled=false; b.textContent="Refresh now" },4000);
};
$("#logscale").onchange=refresh; $("#showblips").onchange=refresh;
// labels can be cut short on a narrow window: on hover, a cut-off label shows its full current
// text (worked out then, so a label that changes - "live 19:18:30" - is never stale)
document.addEventListener("mouseover",e=>{
  const t=e.target.closest?.(".status .cell>span,.livefig .k"); if(!t) return;
  t.title=t.scrollWidth>t.clientWidth?t.textContent.replace(/\s+/g," ").trim():"" });
let resizeT; window.addEventListener("resize",()=>{clearTimeout(resizeT);resizeT=setTimeout(()=>{
  // sparklines redraw now at their new size, rather than staying stretched until the next reading
  document.querySelectorAll("canvas").forEach(c=>{ if(c._spark) spark(c,...c._spark) });
  refresh() },250)});
// the full refresh also pauses while the tab is hidden, and catches up as soon as it's shown
async function loop(){ if(document.visibilityState==="visible"){ try{ await refresh() }catch(e){} } setTimeout(loop,every()) }

// ---------------------------------------------------------------- live strip
// Asks /api/live every 2 s, but only while this page is visible: hidden tabs stop asking, and
// Hearth drops back to its background pace about 30 s later. The last two minutes are kept
// here in the browser for the sparklines - nothing extra is stored.
const LIVE_MS=2000, LIVE_KEEP=60, liveHist={inet:[],router:[],down:[],up:[],cpu:[]};
let liveTimer=null, liveBusy=false, uiVersion=null;  // one poll chain only, however often the tab is hidden and shown
// keep: how many points fill the width; zoom: scale to the values' own range (a temperature
// that moves a few degrees would be a flat line on a scale from zero)
function spark(canvas,series,colors,maxFloor=1e-6,opts={}){
  const {keep=LIVE_KEEP,zoom=false}=opts;
  canvas._spark=[series,colors,maxFloor,opts];  // so a window resize can redraw it straight away
  // draw at the size it's shown (and the screen's pixel density), so it's crisp and never stretched
  const dpr=window.devicePixelRatio||1, cw=Math.round(canvas.clientWidth*dpr), ch=Math.round(canvas.clientHeight*dpr);
  if(canvas.width!==cw||canvas.height!==ch){ canvas.width=cw; canvas.height=ch }
  const g=canvas.getContext("2d"), w=canvas.width, h=canvas.height;
  g.clearRect(0,0,w,h);
  g.lineWidth=1.5*dpr;
  // headroom so a steady value isn't pinned to the top; no fixed floor, so sub-1 ms values still show
  const all=series.flat().filter(v=>v!=null);
  const lo=zoom&&all.length?Math.min(...all)-1:0, max=zoom&&all.length?Math.max(...all)+1:Math.max(maxFloor,...all)*1.25;
  series.forEach((s,i)=>{
    g.strokeStyle=colors[i]; g.beginPath();
    let started=false;
    s.forEach((v,j)=>{ if(v==null){started=false;return}
      const x=w-(s.length-1-j)*(w/(keep-1)), y=h-2-((v-lo)/(max-lo))*(h-4);
      started?g.lineTo(x,y):g.moveTo(x,y); started=true });
    g.stroke();
  });
}
function pushHist(k,v){ liveHist[k].push(v); if(liveHist[k].length>LIVE_KEEP) liveHist[k].shift() }
async function livePoll(){
  liveTimer=null;
  if(liveBusy||document.visibilityState!=="visible") return;  // resumes on visibilitychange
  liveBusy=true;
  try{
    const r=await fetch("/api/live").then(x=>{ if(!x.ok) throw new Error(x.status); return x.json() });
    // colour only for "down": a badge would change the cell's size
    $("#lv-inet").textContent=r.internet_up===false?"down":ms(r.internet_ms);
    $("#lv-inet").style.color=r.internet_up===false?"var(--bad)":"";
    // the dashboard was updated on the server: load the new version instead of running the old one
    if(r.ui){ if(uiVersion==null) uiVersion=r.ui; else if(r.ui!==uiVersion){ location.reload(); return } }
    $("#lv-router").textContent=ms(r.router_ms);
    $("#lv-traffic").textContent=r.down_mbps==null?"–":`↓ ${mbps(r.down_mbps)} ↑ ${mbps(r.up_mbps)}`;
    const busy=r.busiest?`${r.busiest.name} · ${mbps(r.busiest.down_mbps+r.busiest.up_mbps)}`:"nobody much";
    $("#lv-busy").textContent=busy; $("#lv-busy").title=busy;  // a long name is cut short; hover shows it all
    $("#lv-host").textContent=[r.cpu_pct==null?null:`CPU ${Math.round(r.cpu_pct)}%`,
      r.mem_used_pct==null?null:`mem ${Math.round(r.mem_used_pct)}%`].filter(Boolean).join(" · ")||"–";
    $("#lv-note").textContent="live "+new Date(r.ts*1000).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});
    pushHist("inet",r.internet_ms); pushHist("router",r.router_ms); pushHist("down",r.down_mbps); pushHist("up",r.up_mbps);
    pushHist("cpu",r.cpu_pct);
    spark($("#lv-inet-spark"),[liveHist.inet],[CC.orange]);
    spark($("#lv-router-spark"),[liveHist.router],[CC.purple]);
    spark($("#lv-traffic-spark"),[liveHist.down,liveHist.up],[CC.blue,CC.orange]);
    spark($("#lv-host-spark"),[liveHist.cpu],[CC.teal],100/1.25);  // CPU on a fixed 0-100% scale
  }catch(e){ $("#lv-note").textContent="unavailable" }
  liveBusy=false;
  liveTimer=setTimeout(livePoll,LIVE_MS);
}
// shown again: catch the full view up at once and restart the live strip (if it isn't running)
document.addEventListener("visibilitychange",()=>{
  if(document.visibilityState!=="visible") return;
  refresh().catch(()=>{});
  if(!liveTimer&&!liveBusy) livePoll();
});

// phone cards: each cell is labelled with its column's heading (shown before the value on a narrow
// screen). Tables are redrawn all the time, so this follows every change rather than each renderer
function labelTables(){
  for(const t of document.querySelectorAll(".tabpanel table")){
    const heads=[...t.querySelectorAll(":scope>thead>tr:first-child>th")].map(th=>th.textContent.trim());   // this table's first header row
    for(const tr of t.querySelectorAll(":scope>tbody>tr")){
      let col=0;
      for(const td of tr.children){
        const want=!td.hasAttribute("colspan")&&heads[col]||null;
        if(want&&td.dataset.label!==want) td.dataset.label=want; else if(!want&&"label" in td.dataset) delete td.dataset.label;
        col+=+td.getAttribute("colspan")||1;
      }
    }
  }
}
let labelQueued=false;
new MutationObserver(()=>{ if(!labelQueued){ labelQueued=true; requestAnimationFrame(()=>{ labelQueued=false; labelTables() }) } })
  .observe($("main"),{childList:true,subtree:true});
// start: the address says which view (a bare address opens Overview at the last range used)
buildTabs(); themeButton(); showMapAsList(mapAsList);
$("#maplistbtn").onclick=()=>showMapAsList(!mapAsList);
$("#theme").onclick=()=>applyTheme(document.documentElement.dataset.theme==="light"?"dark":"light",true);
matchMedia("(prefers-color-scheme: light)").addEventListener("change",e=>{
  let chosen=null; try{ chosen=localStorage.getItem("hearth_theme") }catch(err){}
  if(chosen!=="light"&&chosen!=="dark") applyTheme(e.matches?"light":"dark",false) });
if(!location.hash) history.replaceState(null,"",hashFor("overview",rangeLabel()));
applyHash(); loop(); livePoll();
