from correlation import classify_host_roles

def test_classify_host_roles_patient_zero():
    # Setup mock host profiles
    host_profiles = {
        "192.168.1.10": {
            "ip": "192.168.1.10",
            "hostname": "workstation-10",
            "infection_score": 150,
            "first_seen": 100.0,
        },
        "192.168.1.20": {
            "ip": "192.168.1.20",
            "hostname": "workstation-20",
            "infection_score": 100,
            "first_seen": 150.0,
        }
    }

    # Setup mock sessions
    sessions = {
        "session-1": {
            "uid": "session-1",
            "orig_h": "192.168.1.10",
            "resp_h": "192.168.1.20",
            "resp_p": 445, # SMB port (lateral movement)
            "score": 50,
            "intel_hits": ["YARA Match"],
            "ts": 150.0
        }
    }

    roles = classify_host_roles(sessions, host_profiles)

    # 192.168.1.10 was seen first (ts=100.0) -> should be PATIENT_ZERO
    assert roles["192.168.1.10"]["role"] == "PATIENT_ZERO"

    # 192.168.1.20 received lateral SMB from 192.168.1.10 -> should be INFECTED
    assert roles["192.168.1.20"]["role"] == "INFECTED"
    assert "192.168.1.10" in roles["192.168.1.20"]["infected_by"]


def test_classify_host_roles_c2_node():
    host_profiles = {
        "192.168.1.10": {
            "ip": "192.168.1.10",
            "infection_score": 150,
            "first_seen": 100.0,
        }
    }

    sessions = {
        "session-1": {
            "uid": "session-1",
            "orig_h": "192.168.1.10",
            "resp_h": "8.8.8.8",
            "resp_p": 443,
            "score": 90,
            "intel_hits": ["C2 beaconing"],
            "ts": 100.0
        }
    }

    # Note that classify_host_roles returns roles for internal hosts in host_profiles
    roles = classify_host_roles(sessions, host_profiles)
    assert roles["192.168.1.10"]["role"] == "PATIENT_ZERO"
