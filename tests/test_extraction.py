from pathlib import Path
from extraction import _parse_host_port, _ioc, _iter_ndjson

def test_parse_host_port_ipv4():
    is_ip, clean_host, port = _parse_host_port("192.168.1.1")
    assert is_ip is True
    assert clean_host == "192.168.1.1"
    assert port is None

def test_parse_host_port_ipv4_with_port():
    is_ip, clean_host, port = _parse_host_port("192.168.1.1:8080")
    assert is_ip is True
    assert clean_host == "192.168.1.1"
    assert port == "8080"

def test_parse_host_port_domain():
    is_ip, clean_host, port = _parse_host_port("example.com")
    assert is_ip is False
    assert clean_host == "example.com"
    assert port is None

def test_parse_host_port_domain_with_port():
    is_ip, clean_host, port = _parse_host_port("example.com:443")
    assert is_ip is False
    assert clean_host == "example.com"
    assert port == "443"

def test_parse_host_port_ipv6():
    is_ip, clean_host, port = _parse_host_port("fe80::1")
    assert is_ip is True
    assert clean_host == "fe80::1"
    assert port is None

def test_parse_host_port_ipv6_bracket_with_port():
    is_ip, clean_host, port = _parse_host_port("[fe80::1]:443")
    assert is_ip is True
    assert clean_host == "fe80::1"
    assert port == "443"

def test_parse_host_port_empty():
    is_ip, clean_host, port = _parse_host_port("")
    assert is_ip is False
    assert clean_host == ""
    assert port is None

def test_ioc_factory():
    ioc_data = _ioc("test_source", ip="1.1.1.1", domain="test.com", port="80", protocol="http")
    assert ioc_data["source_type"] == "test_source"
    assert ioc_data["ip"] == "1.1.1.1"
    assert ioc_data["domain"] == "test.com"
    assert ioc_data["port"] == "80"
    assert ioc_data["protocol"] == "http"
    assert ioc_data["url"] is None
    assert ioc_data["file_hash"] is None
    assert ioc_data["yara_match"] is None

def test_iter_ndjson(tmp_path):
    temp_file = tmp_path / "test.json"
    temp_file.write_text('{"a": 1}\n{"b": 2}\n\n{"c": 3}\n')

    results = list(_iter_ndjson(temp_file))
    assert len(results) == 3
    assert results[0] == {"a": 1}
    assert results[1] == {"b": 2}
    assert results[2] == {"c": 3}

def test_iter_ndjson_missing():
    # Should not raise an error, just log a warning and return empty generator
    results = list(_iter_ndjson(Path("nonexistent_file.json")))
    assert results == []
