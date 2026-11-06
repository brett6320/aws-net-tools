"""Self-contained HTML report for cw_alarm_history.

Renders HistoryReport.to_dict() (the same data as the JSON report), so a saved JSON
report renders the same way. Layout:

  header: account, Region, period, theme toggle
  summary cards: alarms, transitions, times into ALARM, time in ALARM, period length
  alarms: one row per alarm with its state at the start of the period and now,
          transition counts and time in ALARM (including time before the first transition)
  concurrent ALARM intervals: pick alarms and a threshold (default: all of them) to list
          the spans when at least that many were in ALARM at the same time; CSV export
  transitions: one row per state change, filtered in-page by alarm, from/to state,
          text, time window and (when present) history type; UTC or local time;
          "Export CSV" writes the rows currently shown, with the active filters
          recorded in leading "#" lines (optional)
  raw JSON

The transition table is built by the page's own script from the embedded data, so
the export always matches what is on screen. Inline CSS and JS only; no external
resources. Dark by default with an in-page toggle.
"""
from __future__ import annotations

import html
import json
from typing import Any

THEMES = ("dark", "light", "auto")
STATES = ("OK", "ALARM", "INSUFFICIENT_DATA")


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _state_pill(state: str | None) -> str:
    cls = {"OK": "ok", "ALARM": "bad", "INSUFFICIENT_DATA": "warn"}.get(state or "", "")
    return f'<span class="pill {cls}">{_e(state or "?")}</span>'


def _cards(d: dict) -> str:
    n_alarm = d.get("into_alarm_count") or 0
    cards = [
        ("", d.get("alarm_count", 0), "alarms"),
        ("", d.get("transition_count", 0), "state transitions"),
        ("bad" if n_alarm else "", n_alarm, "times into ALARM"),
        ("bad" if d.get("seconds_in_alarm") else "", d.get("time_in_alarm", "-"), "time in ALARM (all alarms)"),
        ("", _period_len(d), "period"),
    ]
    return '<div class="cards">' + "".join(
        f'<div class="stat {cls}"><b>{_e(val)}</b><span>{_e(label)}</span></div>' for cls, val, label in cards
    ) + "</div>"


def _period_len(d: dict) -> str:
    from datetime import datetime
    try:
        a = datetime.fromisoformat(str(d["start"]).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(d["end"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return "-"
    s = int((b - a).total_seconds())
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= size:
            parts.append(f"{s // size}{unit}")
            s %= size
    return " ".join(parts[:2]) or f"{s}s"


def _alarm_rows(d: dict) -> str:
    rows = []
    for a in d.get("alarms", []):
        if a.get("error"):
            rows.append(f'<tr class="err"><td><code>{_e(a["alarm"])}</code></td>'
                        f'<td colspan="7" class="warnmsg">not read: {_e(a["error"])}</td></tr>')
            continue
        exists = "" if a.get("exists", True) else (
            ' <span class="pill warn">deleted</span>' if a.get("transitions") else ' <span class="pill warn">not found</span>')
        rows.append(
            f'<tr><td><code>{_e(a["alarm"])}</code>{exists}</td><td>{_e(a.get("alarm_type") or "?")}</td>'
            f'<td>{_state_pill(a.get("state_at_start"))}</td><td>{_state_pill(a.get("current_state")) if a.get("current_state") else "-"}</td>'
            f'<td class="n">{_e(a.get("transitions", 0))}</td><td class="n{" neg" if a.get("into_alarm") else ""}">{_e(a.get("into_alarm", 0))}</td>'
            f'<td class="n{" neg" if a.get("seconds_in_alarm") else ""}">{_e(a.get("time_in_alarm", "-"))}</td>'
            f'<td class="muted">{_e((a.get("state_transitioned") or a.get("state_updated") or "").replace("T", " ").replace("Z", " UTC"))}</td></tr>'
        )
    return "".join(rows) or '<tr><td colspan="8" class="muted">No alarms</td></tr>'


def _notes(d: dict) -> str:
    out = []
    if d.get("alarms_not_found"):
        out.append('<div class="note warn">Not found (deleted, wrong Region, or misspelt): '
                   + ", ".join(f"<code>{_e(n)}</code>" for n in d["alarms_not_found"]) + "</div>")
    if d.get("errors"):
        out.append('<div class="note bad">Errors: ' + "; ".join(_e(e) for e in d["errors"]) + "</div>")
    return "".join(out)


_LIGHT = ("--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;"
          "--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;"
          "color-scheme:light")

CSS = """
/* Dark is the default; data-theme="light" or "auto" (follow the OS) override it. */
:root{--bg:#0f1419;--card:#192029;--fg:#e6e9ee;--muted:#9aa5b1;--line:#2e3a47;--code:#232d38;--ok:#5fd16a;--okbg:#14301a;--bad:#ff7b6b;--badbg:#3a1714;--warn:#f2c94c;--warnbg:#3a2f0c;--accent:#58a6ff;color-scheme:dark}
:root[data-theme="light"]{LIGHT}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{LIGHT}}
@media print{:root,:root[data-theme]{LIGHT}.themebtn,.filters,.exportbar{display:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:none;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:0 0 12px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted);font-weight:400}.warnmsg{color:var(--warn)}
p.muted{margin:-6px 0 12px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.pill{display:inline-block;padding:0 8px;border-radius:4px;font-weight:600;font-size:12px;background:var(--code);white-space:nowrap}
.pill.ok{color:var(--ok);background:var(--okbg)}.pill.bad{color:var(--bad);background:var(--badbg)}
.pill.warn{color:var(--warn);background:var(--warnbg)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
.stat.bad{border-color:var(--bad)}.stat.bad b{color:var(--bad)}
.note{padding:8px 12px;border-radius:6px;margin-bottom:12px;background:var(--code)}
.note.warn{color:var(--warn);background:var(--warnbg)}.note.bad{color:var(--bad);background:var(--badbg)}
.filters{display:flex;gap:14px 20px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.filters input[type=search],.filters input[type=datetime-local]{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 10px;font:inherit}
.filters input[type=search]{min-width:260px}
.filters label{white-space:nowrap}
.filters fieldset{border:0;padding:0;margin:0;display:inline-flex;gap:10px;align-items:center}
.filters legend{float:left;padding:0;margin-right:4px;color:var(--muted)}
details.dd{position:relative;display:inline-block}
details.dd summary{cursor:pointer;list-style:none;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:5px 10px;white-space:nowrap}
details.dd summary::-webkit-details-marker{display:none}
details.dd .menu{position:absolute;z-index:5;top:110%;left:0;min-width:320px;max-height:320px;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px;box-shadow:0 6px 24px rgba(0,0,0,.35)}
details.dd .menu label{display:block;padding:2px 0;white-space:nowrap}
details.dd .menu .acts{display:flex;gap:8px;margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.exportbar{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin:0 0 10px}
button.btn,.themebtn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
button.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
button.btn.small{padding:1px 8px;font-size:12px}
.tw{overflow-x:auto}
table.grid{border-collapse:collapse;width:100%;font-size:13px}
table.grid th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:6px 10px 6px 0;white-space:nowrap;cursor:pointer;user-select:none}
table.grid th.n{text-align:right}
table.grid th[data-sort]::after{content:"";margin-left:4px;opacity:.5}
table.grid th.asc::after{content:"▲"}table.grid th.desc::after{content:"▼"}
table.grid td{padding:6px 10px 6px 0;vertical-align:top;border-bottom:1px solid var(--line)}
table.grid code{white-space:nowrap;word-break:normal}
table.grid .n{text-align:right;font-variant-numeric:tabular-nums}
table.grid td.ts{white-space:nowrap;font-variant-numeric:tabular-nums}
table.grid td.arrow{white-space:nowrap}
td.neg{color:var(--bad);font-weight:600}
td.reason{max-width:640px}
tr.extra td{background:var(--code);padding:8px 12px}
tr.extra pre{margin:0;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:300px;overflow:auto}
.ongoing{color:var(--muted);font-size:11px;margin-left:4px}
.filters input[type=number]{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 8px;font:inherit;width:70px}
.filters input[type=number]:disabled{opacity:.5}
td.names{max-width:560px}
details.raw summary{cursor:pointer;font-weight:600}
details.raw pre{max-height:480px;overflow:auto;background:var(--code);padding:12px;border-radius:6px;font-size:12px}
footer{color:var(--muted);font-size:12px;margin-top:24px}
""".replace("LIGHT", _LIGHT)

# The page script. DATA is the report dict; the transition table and the CSV export are
# built from the same filtered array so they always agree.
JS = r"""
(function(){
'use strict';
var D=window.DATA,T=D.transitions||[],STATES=['OK','ALARM','INSUFFICIENT_DATA'];
var $=function(id){return document.getElementById(id)};
var pad=function(n){return (n<10?'0':'')+n};
document.querySelector('.themebtn').addEventListener('click',function(){
  var r=document.documentElement,c=r.getAttribute('data-theme');
  if(c==='auto')c=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
  r.setAttribute('data-theme',c==='light'?'dark':'light');});

/* ---- time ---- */
function parseTs(s){return s?new Date(s).getTime():NaN}
function fmtUtc(ms){var d=new Date(ms);return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())}
function fmtLocal(ms){var d=new Date(ms);return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())}
function tzName(){try{return Intl.DateTimeFormat().resolvedOptions().timeZone||'local'}catch(e){return 'local'}}
function offsetLabel(){var o=-new Date().getTimezoneOffset(),s=o<0?'-':'+';o=Math.abs(o);return 'UTC'+s+pad(Math.floor(o/60))+':'+pad(o%60)}
function fmt(ms){return isNaN(ms)?'':(local()?fmtLocal(ms):fmtUtc(ms))}
function local(){return $('local').checked}
/* datetime-local inputs are in the displayed zone: UTC when the local box is off */
function toInput(ms){var d=new Date(ms);if(local())return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
  return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+'T'+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())}
function fromInput(v){if(!v)return NaN;var m=/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d)(?::(\d\d))?$/.exec(v);if(!m)return NaN;
  var a=[+m[1],+m[2]-1,+m[3],+m[4],+m[5],+(m[6]||0)];return local()?new Date(a[0],a[1],a[2],a[3],a[4],a[5]).getTime():Date.UTC(a[0],a[1],a[2],a[3],a[4],a[5])}
function fmtDur(s){if(s==null)return '';s=Math.round(s);if(s<60)return s+'s';var out=[],u=[['d',86400],['h',3600],['m',60],['s',1]];
  for(var i=0;i<u.length;i++){if(s>=u[i][1]){out.push(Math.floor(s/u[i][1])+u[i][0]);s%=u[i][1]}}return out.slice(0,2).join(' ')}

/* ---- concurrent ALARM intervals ---- */
var P0=parseTs(D.start),P1=parseTs(D.end);
function segments(){var segs={},first={};(D.alarms||[]).forEach(function(a){segs[a.alarm]=[]});
  T.forEach(function(t){if(t.history_type!=='StateUpdate')return;var ms=parseTs(t.timestamp);if(!(t.alarm in first))first[t.alarm]=ms;
    if(t.to_state==='ALARM'){(segs[t.alarm]=segs[t.alarm]||[]).push([ms,ms+(t.duration_s||0)*1000])}});
  (D.alarms||[]).forEach(function(a){if(a.state_at_start==='ALARM')segs[a.alarm].unshift([P0,(a.alarm in first)?first[a.alarm]:P1])});
  Object.keys(segs).forEach(function(k){segs[k]=segs[k].filter(function(s){return s[1]>s[0]})});return segs}
var SEGS=segments();
function overlap(sel,n){if(n<1||n>sel.length)return [];var ev=[];sel.forEach(function(name){(SEGS[name]||[]).forEach(function(s){ev.push([s[0],1,name]);ev.push([s[1],0,name])})});
  ev.sort(function(a,b){return a[0]-b[0]||a[1]-b[1]});var out=[],active={},cnt=0,cur=null;
  ev.forEach(function(e){var ts=e[0],name=e[2];if(e[1]===1){if(!active[name])cnt++;active[name]=1;
      if(!cur&&cnt>=n){cur={start:ts,peak:cnt,alarms:{}};Object.keys(active).forEach(function(k){cur.alarms[k]=1})}
      else if(cur){cur.alarms[name]=1;cur.peak=Math.max(cur.peak,cnt)}}
    else{if(active[name]){delete active[name];cnt--}if(cur&&cnt<n){out.push({start:cur.start,end:ts,peak:cur.peak,alarms:Object.keys(cur.alarms).sort()});cur=null}}});
  return out}
var ovRows=[];
function ovSel(){return checked('ov')}
function ovN(sel){return $('ovall').checked?sel.length:Math.max(1,parseInt($('ovn').value,10)||1)}
function renderOverlap(){var sel=ovSel(),n=ovN(sel);if($('ovall').checked)$('ovn').value=sel.length||1;
  ovRows=overlap(sel,n);var tb=$('ovtb'),h='',tot=0;
  ovRows.forEach(function(iv,i){var d=(iv.end-iv.start)/1000;tot+=d;
    h+='<tr><td class="n">'+(i+1)+'</td><td class="ts">'+esc(fmt(iv.start))+'</td><td class="ts">'+esc(fmt(iv.end))+(iv.end>=P1?'<span class="ongoing" title="still in effect at the end of the period">+</span>':'')+'</td>'+
      '<td class="n">'+esc(fmtDur(d))+'</td><td class="n">'+iv.peak+' / '+sel.length+'</td><td class="names">'+iv.alarms.map(function(a){return '<code>'+esc(a)+'</code>'}).join(' ')+'</td></tr>'});
  tb.innerHTML=h||'<tr><td colspan="6" class="muted">'+(sel.length?(n>sel.length?'Threshold exceeds the number of selected alarms':'No interval with '+n+' of '+sel.length+' selected alarms in ALARM at once'):'No alarms selected')+'</td></tr>';
  $('ovcnt').textContent=ovRows.length+' interval'+(ovRows.length===1?'':'s')+(ovRows.length?' · '+fmtDur(tot)+' total':'')+' · threshold '+n+' of '+sel.length;
  document.querySelectorAll('.tzl').forEach(function(e){e.textContent=local()?tzName():'UTC'})}
function ovDescribe(){var sel=ovSel(),n=ovN(sel);return 'selected='+sel.length+' of '+alarmsAll().length+': '+sel.join(' | ')+'; threshold='+($('ovall').checked?'all ('+n+')':n)+'; time='+(local()?tzName():'UTC')}
function exportOverlapCsv(){var lines=[],now=new Date(),sel=ovSel(),n=ovN(sel);
  if($('meta').checked){lines.push('# CloudWatch alarm history: concurrent ALARM intervals');
    lines.push('# account='+(D.account||'?')+'; region='+(D.region||'')+'; period='+(D.start||'')+' -> '+(D.end||'')+'; generated='+(D.generated_at||''));
    lines.push('# filters: '+ovDescribe());lines.push('# rows='+ovRows.length+'; exported='+now.toISOString())}
  lines.push(['n','start_utc','end_utc','start_'+(local()?'local':'utc')+'_display','end_'+(local()?'local':'utc')+'_display','duration_s','duration','ongoing','peak_in_alarm','selected','threshold','alarms','account','region'].map(csvCell).join(','));
  ovRows.forEach(function(iv,i){var d=(iv.end-iv.start)/1000;lines.push([i+1,new Date(iv.start).toISOString(),new Date(iv.end).toISOString(),fmt(iv.start),fmt(iv.end),Math.round(d),fmtDur(d),iv.end>=P1?'yes':'',iv.peak,sel.length,n,iv.alarms.join(' | '),D.account,D.region].map(csvCell).join(','))});
  var stamp=now.toISOString().slice(0,16).replace(/[-:]/g,'').replace('T','-');
  download('alarm_overlap_'+(D.account||'account')+'_'+stamp+'.csv',lines.join('\r\n')+'\r\n')}
function download(name,text){var blob=new Blob(['\ufeff'+text],{type:'text/csv;charset=utf-8'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();
  setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},1000)}
window.cwahOverlap=function(){return {rows:ovRows,desc:ovDescribe()}};

/* ---- filter state ---- */
var rows=T.map(function(t,i){return {i:i,t:t,ms:parseTs(t.timestamp),s:[t.alarm,t.from_state,t.to_state,t.reason,t.summary,t.history_type].join(' ').toLowerCase()}});
var alarms=[];T.forEach(function(t){if(alarms.indexOf(t.alarm)<0)alarms.push(t.alarm)});
(D.alarms||[]).forEach(function(a){if(alarms.indexOf(a.alarm)<0)alarms.push(a.alarm)});
alarms.sort();function alarmsAll(){return alarms}
var htypes=[];T.forEach(function(t){if(htypes.indexOf(t.history_type)<0)htypes.push(t.history_type)});
var sortKey='ms',sortDir=1;

function buildMenu(id,items,prefix){var m=$(id);m.innerHTML='<div class="acts"><button type="button" class="btn small" data-all="1">All</button><button type="button" class="btn small" data-all="0">None</button></div>'+
  items.map(function(a,i){return '<label><input type="checkbox" name="'+prefix+'" value="'+esc(a)+'" checked> '+esc(a)+'</label>'}).join('');
  m.querySelectorAll('[data-all]').forEach(function(b){b.addEventListener('click',function(){m.querySelectorAll('input').forEach(function(c){c.checked=b.dataset.all==='1'});apply()})});
  m.addEventListener('change',apply)}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function checked(name){return [].slice.call(document.querySelectorAll('input[name="'+name+'"]:checked')).map(function(c){return c.value})}
function allChecked(name){var all=document.querySelectorAll('input[name="'+name+'"]');return all.length===document.querySelectorAll('input[name="'+name+'"]:checked').length}

function filters(){
  return {q:$('q').value.trim().toLowerCase(),alarms:checked('al'),allAlarms:allChecked('al'),from:checked('fs'),to:checked('ts'),
    ht:htypes.length>1?checked('ht'):htypes,allHt:htypes.length>1?allChecked('ht'):true,
    ongoing:$('ongoing').checked,winFrom:fromInput($('wfrom').value),winTo:fromInput($('wto').value),inOv:$('ovshow').checked}}

function matches(r,f){var t=r.t;
  if(f.alarms.indexOf(t.alarm)<0)return false;
  if(f.ht.indexOf(t.history_type)<0)return false;
  if(t.history_type==='StateUpdate'){if(f.from.indexOf(t.from_state)<0&&STATES.indexOf(t.from_state)>=0)return false;
    if(f.to.indexOf(t.to_state)<0&&STATES.indexOf(t.to_state)>=0)return false;}
  if(f.ongoing&&!t.ongoing)return false;
  if(f.inOv&&!ovRows.some(function(iv){return r.ms>=iv.start&&r.ms<=iv.end}))return false;
  if(!isNaN(f.winFrom)&&r.ms<f.winFrom)return false;
  if(!isNaN(f.winTo)&&r.ms>f.winTo+59999)return false;
  if(f.q&&r.s.indexOf(f.q)<0)return false;
  return true}

var shown=[];
function apply(){
  renderOverlap();var f=filters();shown=rows.filter(function(r){return matches(r,f)});
  var dir=sortDir;shown.sort(function(a,b){var x=sortVal(a),y=sortVal(b);return (x<y?-1:x>y?1:a.i-b.i)*dir});
  render();describe(f)}
function sortVal(r){var t=r.t;switch(sortKey){case 'alarm':return t.alarm;case 'from':return t.from_state||'';case 'to':return t.to_state||'';
  case 'dur':return t.duration_s==null?-1:t.duration_s;case 'reason':return (t.reason||t.summary||'').toLowerCase();default:return r.ms}}

function pill(s){var c=s==='OK'?'ok':s==='ALARM'?'bad':s==='INSUFFICIENT_DATA'?'warn':'';return '<span class="pill '+c+'">'+esc(s||'?')+'</span>'}
function render(){
  var tb=$('tb'),multi=htypes.length>1,h='';
  shown.forEach(function(r){var t=r.t,su=t.history_type==='StateUpdate';
    h+='<tr data-i="'+r.i+'"><td class="ts">'+esc(fmt(r.ms))+'</td><td><code>'+esc(t.alarm)+'</code></td>'+
      (multi?'<td>'+esc(t.history_type)+'</td>':'')+
      '<td class="arrow">'+(su?pill(t.from_state)+' → '+pill(t.to_state):'<span class="muted">—</span>')+'</td>'+
      '<td class="n">'+(su?esc(fmtDur(t.duration_s))+(t.ongoing?'<span class="ongoing" title="still in this state at the end of the period">+</span>':''):'')+'</td>'+
      '<td class="reason">'+esc(su?(t.reason||''):(t.summary||''))+(t.reason_data?' <button type="button" class="btn small more" title="Show evaluation data">…</button>':'')+'</td></tr>'});
  tb.innerHTML=h||'<tr><td colspan="'+(multi?6:5)+'" class="muted">No transitions match the filters</td></tr>';
  var n=shown.length,a=0,secs=0;shown.forEach(function(r){if(r.t.to_state==='ALARM'){a++;secs+=r.t.duration_s||0}});
  $('cnt').textContent=n+' of '+rows.length+' transitions · '+a+' into ALARM · '+(fmtDur(secs)||'0s')+' in ALARM';
  $('tzlabel').textContent=local()?tzName()+' ('+offsetLabel()+')':'UTC';
  $('wlabel').textContent=local()?'local':'UTC';
  tb.querySelectorAll('button.more').forEach(function(b){b.addEventListener('click',function(){
    var tr=b.closest('tr'),nx=tr.nextElementSibling;if(nx&&nx.classList.contains('extra')){nx.remove();return}
    var t=T[+tr.dataset.i],x=document.createElement('tr');x.className='extra';
    x.innerHTML='<td colspan="'+tr.children.length+'"><pre>'+esc(JSON.stringify(t.reason_data,null,2))+'</pre></td>';tr.after(x)})});
  document.querySelectorAll('th[data-sort]').forEach(function(th){th.className=th.className.replace(/\b(asc|desc)\b/g,'').trim();
    if(th.dataset.sort===sortKey)th.classList.add(sortDir>0?'asc':'desc')});}

/* human description of the active filters: shown on the page and written into the CSV */
function describe(f){
  var parts=[];
  parts.push('alarms='+(f.allAlarms?'all ('+alarms.length+')':f.alarms.length+' of '+alarms.length+': '+f.alarms.join(' | ')));
  parts.push('from='+(f.from.length===STATES.length?'any':f.from.join('/')||'none'));
  parts.push('to='+(f.to.length===STATES.length?'any':f.to.join('/')||'none'));
  if(htypes.length>1)parts.push('history='+(f.allHt?'all':f.ht.join('/')||'none'));
  if(f.ongoing)parts.push('ongoing only');
  if(!isNaN(f.winFrom)||!isNaN(f.winTo))parts.push('window='+(isNaN(f.winFrom)?'…':fmt(f.winFrom))+' → '+(isNaN(f.winTo)?'…':fmt(f.winTo))+' '+(local()?offsetLabel():'UTC'));
  if(f.q)parts.push('text="'+f.q+'"');
  if(f.inOv)parts.push('inside concurrent-ALARM intervals ('+ovDescribe()+')');
  parts.push('time='+(local()?tzName():'UTC'));
  var s=parts.join('; ');$('fdesc').textContent=s;return s}
function isFiltered(f){return f.inOv||!f.allAlarms||f.from.length!==STATES.length||f.to.length!==STATES.length||!f.allHt||f.ongoing||f.q||!isNaN(f.winFrom)||!isNaN(f.winTo)}

/* ---- CSV export of the rows on screen ---- */
function csvCell(v){v=v==null?'':String(v);if(/^[=+\-@]/.test(v))v="'"+v;return /[",\r\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v}
function buildCsv(){
  var f=filters(),desc=describe(f),lines=[],now=new Date();
  if($('meta').checked){
    lines.push('# CloudWatch alarm history export');
    lines.push('# account='+(D.account||'?')+'; region='+(D.region||'')+'; period='+(D.start||'')+' -> '+(D.end||'')+'; generated='+(D.generated_at||''));
    lines.push('# filters: '+desc);
    lines.push('# rows='+shown.length+' of '+rows.length+'; exported='+now.toISOString()+'; sort='+sortKey+(sortDir>0?' asc':' desc'));
  }
  var cols=['alarm','alarm_type','timestamp_utc','timestamp_'+(local()?'local':'utc')+'_display','from_state','to_state','duration_s','duration','ongoing','reason','account','region','history_type','summary'];
  lines.push(cols.map(csvCell).join(','));
  shown.forEach(function(r){var t=r.t;lines.push([t.alarm,t.alarm_type,t.timestamp,fmt(r.ms),t.from_state,t.to_state,
    t.duration_s==null?'':Math.round(t.duration_s),t.duration_s==null?'':fmtDur(t.duration_s),t.ongoing?'yes':'',t.reason,D.account,D.region,t.history_type,t.summary].map(csvCell).join(','))});
  var stamp=now.toISOString().slice(0,16).replace(/[-:]/g,'').replace('T','-');
  var name='alarm_history_'+(D.account||'account')+'_'+stamp+(isFiltered(f)?'_filtered':'')+'.csv';
  return {name:name,text:lines.join('\r\n')+'\r\n'}}
window.cwahCsv=buildCsv; /* same text the Export button saves; handy for scripting and tests */
function exportCsv(){var out=buildCsv();download(out.name,out.text)}

/* ---- wire up ---- */
buildMenu('almenu',alarms,'al');
buildMenu('ovmenu',alarms,'ov');
if(D.overlap_threshold&&D.overlap_threshold!=='all'){$('ovall').checked=false;$('ovn').disabled=false;$('ovn').value=D.overlap_threshold}
$('ovall').addEventListener('change',function(){$('ovn').disabled=$('ovall').checked;apply()});
$('ovn').addEventListener('input',apply);$('ovshow').addEventListener('change',apply);$('ovexport').addEventListener('click',exportOverlapCsv);
if(htypes.length>1){$('htwrap').style.display='';buildMenu('htmenu',htypes,'ht')}
['q','ongoing'].forEach(function(id){$(id).addEventListener('input',apply);$(id).addEventListener('change',apply)});
document.querySelectorAll('input[name="fs"],input[name="ts"]').forEach(function(c){c.addEventListener('change',apply)});
$('wfrom').addEventListener('change',apply);$('wto').addEventListener('change',apply);
$('local').addEventListener('change',function(){
  /* keep the window at the same instants when the display zone changes: read the inputs in the old zone */
  var on=$('local').checked;$('local').checked=!on;var a=fromInput($('wfrom').value),b=fromInput($('wto').value);$('local').checked=on;
  $('wfrom').value=isNaN(a)?'':toInput(a);$('wto').value=isNaN(b)?'':toInput(b);apply()});
$('reset').addEventListener('click',function(){$('q').value='';$('ongoing').checked=false;$('ovshow').checked=false;$('wfrom').value='';$('wto').value='';
  document.querySelectorAll('#almenu input,#htmenu input,input[name="fs"],input[name="ts"]').forEach(function(c){c.checked=true});sortKey='ms';sortDir=1;apply()});
$('export').addEventListener('click',exportCsv);
document.querySelectorAll('th[data-sort]').forEach(function(th){th.addEventListener('click',function(){
  if(sortKey===th.dataset.sort)sortDir=-sortDir;else{sortKey=th.dataset.sort;sortDir=1}apply()})});
document.addEventListener('click',function(e){document.querySelectorAll('details.dd[open]').forEach(function(d){if(!d.contains(e.target))d.removeAttribute('open')})});
apply();
})();
"""


def render_html(d: dict, title: str | None = None, theme: str = "dark") -> str:
    """HTML for one report dict (HistoryReport.to_dict() or a saved JSON report)."""
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    page_title = title or "CloudWatch Alarm History"
    raw = json.dumps(d, indent=2, default=str)
    data = json.dumps(d, default=str).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    multi = len({t.get("history_type") for t in d.get("transitions", [])}) > 1
    state_boxes = lambda name: "".join(  # noqa: E731
        f'<label><input type="checkbox" name="{name}" value="{s}" checked> {s}</label>' for s in STATES)
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}: {_e(d.get("account") or d.get("region"))}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">State transitions for {_e(d.get("alarm_count", 0))} alarm{"s" if d.get("alarm_count", 0) != 1 else ""} ·
account <code>{_e(d.get("account") or "?")}</code> · {_e(d.get("region"))} · generated {_e(d.get("generated_at"))}</div>
<div class="muted">Period <code>{_e(d.get("start"))}</code> → <code>{_e(d.get("end"))}</code> (UTC)</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
{_notes(d)}
{_cards(d)}
<div class="card"><h3>Alarms</h3>
<p class="muted">State at the start of the period is the state the first transition left; with no transitions it is the current state
when that state began before the period, else unknown. Time in ALARM includes time before the first transition and runs to the end of the period for alarms still in ALARM.</p>
<div class="tw"><table class="grid" id="alarms"><thead><tr><th>Alarm</th><th>Type</th><th>At start</th><th>Now</th>
<th class="n">Transitions</th><th class="n">Into ALARM</th><th class="n">Time in ALARM</th><th>Last state change</th></tr></thead>
<tbody>{_alarm_rows(d)}</tbody></table></div></div>
<div class="card"><h3>Concurrent ALARM intervals</h3>
<p class="muted">Spans when at least the threshold number of the selected alarms were in ALARM at the same time. An alarm in
ALARM at the start of the period counts from the period start. Back-to-back spans (one alarm clearing as another fires) do not overlap.</p>
<div class="filters">
<details class="dd"><summary>Alarms ▾</summary><div class="menu" id="ovmenu"></div></details>
<label><input type="checkbox" id="ovall" checked> All selected</label>
<label>At least <input type="number" id="ovn" min="1" step="1" value="1" disabled> in ALARM</label>
<label><input type="checkbox" id="ovshow"> Only transitions inside these intervals</label>
<button type="button" class="btn" id="ovexport">⬇ Export intervals CSV</button>
<span class="muted" id="ovcnt"></span></div>
<div class="tw"><table class="grid" id="ov"><thead><tr><th>#</th><th>Start (<span class="tzl">UTC</span>)</th><th>End (<span class="tzl">UTC</span>)</th>
<th class="n">Duration</th><th class="n">Peak in ALARM</th><th>Alarms in ALARM during the interval</th></tr></thead><tbody id="ovtb"></tbody></table></div>
</div>
<div class="card"><h3>Transitions</h3>
<div class="filters">
<input type="search" id="q" placeholder="Filter: alarm, state, reason">
<details class="dd"><summary>Alarms ▾</summary><div class="menu" id="almenu"></div></details>
<fieldset><legend>From</legend>{state_boxes("fs")}</fieldset>
<fieldset><legend>To</legend>{state_boxes("ts")}</fieldset>
<span id="htwrap" style="display:{"" if multi else "none"}"><details class="dd"><summary>History types ▾</summary><div class="menu" id="htmenu"></div></details></span>
<label><input type="checkbox" id="ongoing"> Still in state at period end</label>
<label>Window (<span id="wlabel">UTC</span>) <input type="datetime-local" id="wfrom" step="60"> → <input type="datetime-local" id="wto" step="60"></label>
<label><input type="checkbox" id="local"> Local time</label>
<button type="button" class="btn" id="reset">Reset filters</button>
</div>
<div class="exportbar"><button type="button" class="btn primary" id="export">⬇ Export CSV</button>
<label title="Leading lines starting with # record the account, period and active filters"><input type="checkbox" id="meta" checked> Include filter summary in CSV</label>
<span class="muted">Showing <span id="cnt"></span></span></div>
<div class="muted" style="margin-bottom:8px">Filters: <span id="fdesc"></span></div>
<div class="tw"><table class="grid" id="tr"><thead><tr><th data-sort="ms">Time (<span id="tzlabel">UTC</span>)</th><th data-sort="alarm">Alarm</th>{"<th>History</th>" if multi else ""}
<th data-sort="to">From → To</th><th class="n" data-sort="dur">In new state</th><th data-sort="reason">Reason</th></tr></thead>
<tbody id="tb"></tbody></table></div>
<p class="muted" style="margin:10px 0 0">"In new state" is the time until the alarm's next state change; <b>+</b> marks alarms still in that state at the end of the period.
Export CSV writes the rows currently shown; the first lines (starting with #) record the active filters.</p>
</div>
<div class="card"><details class="raw"><summary>Raw report JSON</summary><pre>{_e(raw)}</pre></details></div>
<footer>Read-only. CloudWatch keeps alarm history for {_e(d.get("retention_days", 30))} days, including for deleted alarms.</footer>
</main><script>window.DATA={data};</script><script>{JS}</script></body></html>
"""
