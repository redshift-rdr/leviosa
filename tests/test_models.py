from core.models import Param, LeviosaRequest, LeviosaResponse, LeviosaContext


def test_param_fields():
    p = Param(type="cookie", name="session", value="abc")
    assert p.type == "cookie"
    assert p.name == "session"
    assert p.value == "abc"


def test_leviosa_request_fields():
    req = LeviosaRequest(method="GET", url="http://example.com", headers=[], params=[])
    assert req.method == "GET"
    assert req.url == "http://example.com"
    assert req.headers == []
    assert req.params == []


def test_leviosa_request_hashkey_defaults_none():
    req = LeviosaRequest(method="GET", url="http://example.com", headers=[], params=[])
    assert req.hashkey is None


def test_leviosa_response_fields():
    req = LeviosaRequest(method="GET", url="http://x.com", headers=[], params=[])
    resp = LeviosaResponse(status=200, headers={"Content-Type": "text/html"}, body=b"hello", request=req)
    assert resp.status == 200
    assert resp.headers == {"Content-Type": "text/html"}
    assert resp.body == b"hello"
    assert resp.request is req


def test_context_defaults_to_empty_dict():
    ctx = LeviosaContext()
    assert ctx.data == {}


def test_context_not_shared_default():
    ctx1 = LeviosaContext()
    ctx2 = LeviosaContext()
    ctx1.data["key"] = "value"
    assert "key" not in ctx2.data
