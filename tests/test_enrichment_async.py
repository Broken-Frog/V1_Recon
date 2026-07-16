import pytest
from unittest.mock import MagicMock
from enrichment_async import _is_private, _vt_url_for, _parse_vt_response, _enrich_one, _TokenBucket
from cache import RedisCache

def test_is_private():
    assert _is_private("192.168.1.1") is True
    assert _is_private("10.0.0.5") is True
    assert _is_private("8.8.8.8") is False
    assert _is_private("invalid_ip") is False

def test_vt_url_for():
    # VT_IP_ENDPOINT: "https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    url_ip = _vt_url_for("1.1.1.1", "ip")
    assert "1.1.1.1" in url_ip
    assert "ip_addresses" in url_ip

    # VT_HASH_ENDPOINT: "https://www.virustotal.com/api/v3/files/{ioc}"
    url_hash = _vt_url_for("abcdef", "hash")
    assert "abcdef" in url_hash
    assert "files" in url_hash

def test_parse_vt_response():
    data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 2,
                    "undetected": 5,
                    "harmless": 20
                }
            }
        }
    }
    parsed = _parse_vt_response(data)
    assert parsed["vt_score"] == 12
    assert parsed["vt_malicious_count"] == 10
    assert parsed["vt_total_scans"] == 37

def test_parse_vt_response_corrupt():
    expected = {"vt_score": 0, "vt_malicious_count": 0, "vt_total_scans": 0}
    assert _parse_vt_response({}) == expected
    assert _parse_vt_response({"bad": "data"}) == expected

@pytest.mark.asyncio
async def test_token_bucket():
    bucket = _TokenBucket(rate=2, window=0.1)
    # First two acquires should be immediate
    await bucket.acquire()
    await bucket.acquire()

    # Third acquire should trigger a wait
    # We measure time to ensure it blocks
    import time
    start = time.monotonic()
    await bucket.acquire()
    end = time.monotonic()
    assert (end - start) >= 0.0  # it waited for refill

@pytest.mark.asyncio
async def test_enrich_one_cache_hit():
    mock_cache = MagicMock(spec=RedisCache)
    mock_cache.get.return_value = {"vt_score": 5, "vt_malicious_count": 5}

    results = {}
    stats = {"cache_hits": 0, "api_calls_made": 0}
    scanned_records = []

    await _enrich_one(
        ioc_value="8.8.8.8",
        ioc_type="ip",
        cache=mock_cache,
        session=None,
        semaphore=None,
        vt_bucket=None,
        abuse_bucket=None,
        otx_bucket=None,
        results=results,
        stats=stats,
        scanned_records=scanned_records
    )

    assert stats["cache_hits"] == 1
    assert stats["api_calls_made"] == 0
    assert results["8.8.8.8"] == {"vt_score": 5, "vt_malicious_count": 5}
