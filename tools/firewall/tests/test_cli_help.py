import io
import os
import subprocess
import sys
import tokenize

import pytest

from conftest import PY312, ROOT, TOOLS


@pytest.mark.parametrize("tool", TOOLS)
def test_help_exits_zero(tool):
    proc = subprocess.run([sys.executable, str(ROOT / f"{tool}.py"), "--help"], capture_output=True, text=True,
                          timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage:")


def same_quote_nesting(path) -> list[int]:
    """Lines where a string inside an f-string replacement field reuses an enclosing f-string's quote
    character: valid only from Python 3.12 (PEP 701). Needs the 3.12+ tokenizer."""
    stack, bad = [], []
    for tok in tokenize.generate_tokens(io.StringIO(path.read_text(encoding="utf-8")).readline):
        if tok.type == tokenize.FSTRING_START:
            q = tok.string.lstrip("rRfFbB")[:1]
            if q in stack:
                bad.append(tok.start[0])
            stack.append(q)
        elif tok.type == tokenize.FSTRING_END:
            stack.pop()
        elif tok.type == tokenize.STRING and stack and tok.string.lstrip("rRbBuU")[:1] in stack:
            bad.append(tok.start[0])
    return bad


SOURCES = sorted(p.relative_to(ROOT).as_posix() for p in [*ROOT.glob("*.py"), *ROOT.glob("lib/*.py")])


@pytest.mark.parametrize("rel", SOURCES)
def test_source_compiles_on_python_311(rel):
    path = ROOT / rel
    if PY312:
        assert same_quote_nesting(path) == []
    else:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
