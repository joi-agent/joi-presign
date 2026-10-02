import io
import json
import urllib.error

from joi_presign.net import NetLookups


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_opener(routes):
    """routes: list of (url_substring, body_substring_or_None, response) where response is a dict,
    an int HTTP error code, or an exception instance."""
    calls = []

    def opener(req, timeout):
        assert timeout and timeout <= 10
        body = req.data.decode() if req.data else ""
        calls.append((req.full_url, body))
        for url_part, body_part, resp in routes:
            if url_part in req.full_url and (body_part is None or body_part in body):
                if isinstance(resp, int):
                    raise urllib.error.HTTPError(req.full_url, resp, "err", {}, None)
                if isinstance(resp, Exception):
                    raise resp
                return FakeResponse(json.dumps(resp).encode())
        raise urllib.error.URLError("no route")

    opener.calls = calls
    return opener


def test_code_kind_variants(tmp_path):
    L = NetLookups(cache_dir=str(tmp_path), opener=make_opener([
        ("publicnode", '"0xaaaa', {"result": "0x"}),
        ("publicnode", '"0xbbbb', {"result": "0xef0100" + "12" * 20}),
        ("publicnode", '"0xcccc', {"result": "0x6080604052"}),
    ]))
    assert L.code_kind(1, "0xaaaa" + "0" * 36) == "none"
    assert L.code_kind(1, "0xbbbb" + "0" * 36) == "7702"
    assert L.code_kind(1, "0xcccc" + "0" * 36) == "contract"
    assert L.code_kind(1, "0xdddd" + "0" * 36) is None  # network failure -> unknown
    assert L.code_kind(999, "0xaaaa" + "0" * 36) is None  # unsupported chain


def test_tx_count(tmp_path):
    L = NetLookups(cache_dir=str(tmp_path), opener=make_opener([("arbitrum", None, {"result": "0x1f"})]))
    assert L.tx_count(42161, "0x" + "1" * 40) == 31


def test_sourcify(tmp_path):
    L = NetLookups(cache_dir=str(tmp_path), opener=make_opener([
        ("/1/0xaaaa", None, {"match": "exact_match"}),
        ("/1/0xbbbb", None, 404),
        ("/1/0xcccc", None, 500),
    ]))
    assert L.sourcify_verified(1, "0xaaaa" + "0" * 36) is True
    assert L.sourcify_verified(1, "0xbbbb" + "0" * 36) is False
    assert L.sourcify_verified(1, "0xcccc" + "0" * 36) is None


def test_fourbyte_sorted_and_cached(tmp_path):
    opener = make_opener([("4byte", None, {"results": [
        {"id": 900, "text_signature": "spam_x(uint256)"},
        {"id": 5, "text_signature": "approve(address,uint256)"}]})])
    L = NetLookups(cache_dir=str(tmp_path), opener=opener)
    assert L.selector_signatures("0x095ea7b3") == ["approve(address,uint256)", "spam_x(uint256)"]
    assert L.selector_signatures("0x095ea7b3")[0] == "approve(address,uint256)"
    assert len(opener.calls) == 1  # second call served from the file cache
    L2 = NetLookups(cache_dir=str(tmp_path), opener=make_opener([]))
    assert L2.selector_signatures("0x095ea7b3")[0] == "approve(address,uint256)"


def test_fourbyte_down(tmp_path):
    L = NetLookups(cache_dir=str(tmp_path), opener=make_opener([("4byte", None, TimeoutError("slow"))]))
    assert L.selector_signatures("0x12345678") is None
