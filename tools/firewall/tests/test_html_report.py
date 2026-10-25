import json
import re

from lib import html_report

TABLE = {"id": "t", "title": "Things", "columns": [["name", "Name"], ["tags", "Tags"]],
         "rows": [{"name": "a", "tags": ["x", "y"]}, {"name": "b", "tags": []}], "filters": ["name"]}


def block(html: str, element_id: str) -> str:
    """Text of the <script id=...> element."""
    m = re.search(rf'<script id="{element_id}" type="application/json">(.*?)</script>', html, re.S)
    assert m, element_id
    return m.group(1)


def test_render_embeds_data_as_json():
    out = html_report.render("Report", meta=["line 1"], cards=[(3, "groups")], tables=[TABLE])
    assert out.startswith("<!doctype html>")
    data = json.loads(block(out, "data"))
    assert data == {"title": "Report", "meta": ["line 1"], "cards": [[3, "groups"]], "tables": [TABLE],
                    "extra_html": ""}
    assert 'id="extra-data"' not in out


def test_title_is_escaped():
    out = html_report.render("A <b>bold</b> & co", tables=[])
    assert "<title>A &lt;b>bold&lt;/b> &amp; co</title>" in out
    assert json.loads(block(out, "data"))["title"] == "A <b>bold</b> & co"


def test_script_breakout_in_cell_is_neutralised():
    payload = "</script><!--<script>alert(1)</script>"
    out = html_report.render("x", tables=[{**TABLE, "rows": [{"name": payload, "tags": [payload]}]}],
                             cards=[(payload, payload)], meta=[payload], extra_html="")
    assert payload not in out
    assert "<!--" not in out
    # only the template's own closing tags remain
    assert out.count("</script") == html_report.TEMPLATE.count("</script")
    raw = block(out, "data")
    assert "<" not in raw
    data = json.loads(raw)
    assert data["tables"][0]["rows"][0]["name"] == payload
    assert data["meta"] == [payload]


def test_extra_data_and_script():
    out = html_report.render("x", tables=[], extra_data={"k": "<v>"}, extra_script='var s = "</script>";')
    raw = block(out, "extra-data")
    assert "<" not in raw and json.loads(raw) == {"k": "<v>"}
    assert 'var s = "<\\/script>";' in out
    assert out.count("</script") == html_report.TEMPLATE.count("</script") + 1   # + the extra-data element


def test_extra_data_string_embedded_unchanged_except_lt():
    text = json.dumps({"a": "b<c"})
    out = html_report.render("x", tables=[], extra_data=text)
    assert block(out, "extra-data") == text.replace("<", "\\u003c")


def test_placeholders_in_data_are_not_substituted():
    out = html_report.render("__DATA__ __EXTRA_SCRIPT__", tables=[{**TABLE, "rows": [{"name": "__TITLE__"}]}],
                             extra_script="console.log('marker')")
    assert "<title>__DATA__ __EXTRA_SCRIPT__</title>" in out
    data = json.loads(block(out, "data"))
    assert data["tables"][0]["rows"][0]["name"] == "__TITLE__"
    assert out.count("console.log('marker')") == 1


def test_default_str_for_non_json_values(tmp_path):
    import datetime as dt
    out = html_report.render("x", tables=[{**TABLE, "rows": [{"name": dt.date(2026, 1, 2)}]}])
    assert json.loads(block(out, "data"))["tables"][0]["rows"][0]["name"] == "2026-01-02"


def test_write(tmp_path):
    path = tmp_path / "r.html"
    html_report.write(path, "T", tables=[TABLE])
    assert path.read_text(encoding="utf-8") == html_report.render("T", tables=[TABLE])
