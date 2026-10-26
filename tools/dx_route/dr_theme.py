"""Report look shared with the other tools' HTML reports (copied from ipam_locate's il_export,
plus a terminal block for the router output)."""

THEME_JS = (
    "document.querySelector('.themebtn').addEventListener('click',function(){"
    "var r=document.documentElement,c=r.getAttribute('data-theme');"
    "if(c==='auto')c=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';"
    "r.setAttribute('data-theme',c==='light'?'dark':'light');});"
)

_LIGHT = ("--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;"
          "--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;"
          "--hit:#e8f1fc;color-scheme:light")

CSS = """
/* Dark is the default; data-theme="light" or "auto" (follow the OS) override it. */
:root{--bg:#0f1419;--card:#192029;--fg:#e6e9ee;--muted:#9aa5b1;--line:#2e3a47;--code:#232d38;--ok:#5fd16a;--okbg:#14301a;--bad:#ff7b6b;--badbg:#3a1714;--warn:#f2c94c;--warnbg:#3a2f0c;--accent:#58a6ff;--hit:#16283d;color-scheme:dark}
:root[data-theme="light"]{LIGHT}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{LIGHT}}
@media print{:root,:root[data-theme]{LIGHT}.themebtn{display:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:0 0 12px}
h5{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:12px 0 6px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
code.big{font-size:15px;font-weight:600}
a{color:var(--accent)}
.muted{color:var(--muted);font-weight:400}.nm{color:var(--muted)}.warnmsg{color:var(--warn)}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-bottom:16px}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
nav.toc a{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 12px;text-decoration:none;color:var(--fg)}
.query{margin-bottom:40px}
.ahead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.answer{border-left:4px solid var(--accent)}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:600;background:var(--code)}
.badge.ok{color:var(--ok);background:var(--okbg)}.badge.bad{color:var(--bad);background:var(--badbg)}
.badge.warn{color:var(--warn);background:var(--warnbg)}
.pill{display:inline-block;padding:0 8px;border-radius:4px;font-weight:600;font-size:12px;background:var(--code)}
.chip{display:inline-flex;align-items:center;gap:6px;margin:1px 6px 1px 0;vertical-align:middle}
.ico{flex:none}
table.kv{border-collapse:collapse;width:100%;margin-top:8px}
table.kv th{text-align:left;vertical-align:top;color:var(--muted);font-weight:500;padding:5px 12px 5px 0;width:24%;white-space:nowrap}
table.kv td{padding:5px 0;vertical-align:top}
.tw{overflow-x:auto}
table.grid{border-collapse:collapse;width:100%;font-size:13px}
table.grid th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:6px 10px 6px 0;white-space:nowrap}
table.grid td{border-bottom:1px solid var(--line);padding:6px 10px 6px 0;vertical-align:top}
ul.plain{list-style:none;margin:0;padding:0}ul.plain li{padding:2px 0}
ul.tree,ul.tree ul{list-style:none;margin:0;padding:0}
ul.tree ul{margin-left:14px;padding-left:16px;border-left:1px dashed var(--line)}
ul.tree li{position:relative;padding:3px 0}
ul.tree ul>li::before{content:"";position:absolute;left:-16px;top:16px;width:12px;border-top:1px dashed var(--line)}
.tn{display:inline-flex;align-items:center;flex-wrap:wrap;gap:8px;padding:4px 8px;border:1px solid var(--line);border-radius:8px;background:var(--bg)}
.tn.acct{border-style:dashed}
.tn.hit{border-color:var(--accent);background:var(--hit);font-weight:600}
.tl{display:inline-flex;align-items:center}.td{font-size:12.5px}
details.raw summary{cursor:pointer;font-weight:600}
details.raw pre{max-height:480px;overflow:auto;background:var(--code);padding:12px;border-radius:6px;font-size:12px}
.themebtn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
footer{color:var(--muted);font-size:12px;margin-top:24px}
pre.term{margin:0;overflow:auto;background:var(--code);padding:12px 14px;border-radius:6px;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}
table.grid code{white-space:nowrap;word-break:normal}
""".replace("LIGHT", _LIGHT)
