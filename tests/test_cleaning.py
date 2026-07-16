from cleaning import _is_private_ip, _dedup_key, _is_empty, clean_and_deduplicate

def test_is_private_ip():
    assert _is_private_ip("192.168.1.5") is True
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("127.0.0.1") is True
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("example.com") is False  # Invalid IP address strings should return False
    assert _is_private_ip("") is False

def test_dedup_key():
    ioc1 = {"ip": "1.1.1.1", "domain": "example.com", "file_hash": "abc", "port": 80}
    ioc2 = {"ip": "1.1.1.1 ", "domain": "EXAMPLE.COM", "file_hash": "abc", "port": "80"}

    # Whitespace and capitalization differences should result in the same key
    key1 = _dedup_key(ioc1)
    key2 = _dedup_key(ioc2)
    assert key1 == key2
    assert len(key1) == 64

def test_is_empty():
    assert _is_empty({}) is True
    assert _is_empty({"ip": "", "domain": None}) is True
    assert _is_empty({"ip": "1.1.1.1"}) is False
    assert _is_empty({"file_hash": "abc"}) is False

def test_clean_and_deduplicate():
    raw_iocs = [
        # 1. Empty record -> should be dropped
        {},
        # 2. Private loopback -> should be dropped
        {"ip": "127.0.0.1", "source_type": "zeek_conn"},
        # 3. Private class C -> internal zone, kept, tagged is_private
        {"ip": "192.168.1.100", "source_type": "zeek_conn", "timestamp": 100},
        # 4. Same class C but later -> should be merged into #3
        {"ip": "192.168.1.100", "source_type": "zeek_conn", "timestamp": 120, "suricata_alert": "Test Alert"},
        # 5. External IP
        {"ip": "8.8.8.8", "source_type": "zeek_conn", "timestamp": 200},
    ]

    cleaned, stats = clean_and_deduplicate(raw_iocs)

    assert stats["input_count"] == 5
    assert stats["dropped_empty"] == 1
    assert stats["dropped_special_ips"] == 1 # 127.0.0.1 (loopback) is dropped under SPECIFIED/LOOPBACK check
    assert stats["dropped_dedup"] == 1
    assert stats["output_count"] == 2 # 192.168.1.100 and 8.8.8.8

    # Verify internal host classification
    internal_ioc = next(x for x in cleaned if x["ip"] == "192.168.1.100")
    assert internal_ioc["network_zone"] == "INTERNAL"
    assert internal_ioc["is_private"] is True
    assert internal_ioc["timestamp"] == 100

    external_ioc = next(x for x in cleaned if x["ip"] == "8.8.8.8")
    assert external_ioc["network_zone"] == "EXTERNAL"
    assert external_ioc.get("is_private") is not True
