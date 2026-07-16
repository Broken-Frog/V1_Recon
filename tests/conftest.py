import os

# Configure mock API keys and a separate Redis database for testing before config or modules load
os.environ["VT_API_KEY"] = "mock_vt_api_key_12345"
os.environ["ABUSEIPDB_API_KEY"] = "mock_abuseipdb_api_key_12345"
os.environ["OTX_API_KEY"] = "mock_otx_api_key_12345"
os.environ["REDIS_DB"] = "9"  # Separate DB to prevent interference with developer environments
os.environ["PROCESSED_DIR"] = "test_processed"
os.environ["OUTPUT_DIR"] = "test_output"
