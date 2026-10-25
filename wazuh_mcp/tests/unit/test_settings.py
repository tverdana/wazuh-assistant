import pytest

from wazuh_mcp.settings import LabOnlyError, load_settings

LAB_ENV = {
    "WAZUH_API_URL": "https://127.0.0.1:55000",
    "WAZUH_API_USER": "assistant_api_ro",
    "WAZUH_API_PASSWORD": "api-secret-value",
    "WAZUH_API_CA": "/lab/certs/wazuh-api.crt",
    "WAZUH_INDEXER_URL": "https://127.0.0.1:9200",
    "WAZUH_INDEXER_USER": "assistant_idx_ro",
    "WAZUH_INDEXER_PASSWORD": "idx-secret-value",
    "WAZUH_INDEXER_CA": "/lab/certs/root-ca.pem",
}


def _env(tmp_path, **overrides):
    env = {"WAZUH_ENV_FILE": str(tmp_path / "none.env"), **LAB_ENV, **overrides}
    return {k: v for k, v in env.items() if v is not None}


def test_reads_env_file(tmp_path):
    env_file = tmp_path / "readonly.env"
    env_file.write_text(
        "# comment\n" + "\n".join(f"{k}={v}" for k, v in LAB_ENV.items())
    )
    s = load_settings({"WAZUH_ENV_FILE": str(env_file)})
    assert s.api_user == "assistant_api_ro"
    assert s.indexer_tls_name == "wazuh.indexer"


def test_environment_overrides_file(tmp_path):
    s = load_settings(_env(tmp_path, WAZUH_API_USER="other_ro"))
    assert s.api_user == "other_ro"


@pytest.mark.parametrize(
    "key,url",
    [
        ("WAZUH_API_URL", "https://wazuh.prod.example.com:55000"),
        ("WAZUH_INDEXER_URL", "https://10.0.0.5:9200"),
    ],
)
def test_refuses_non_lab_hosts(tmp_path, key, url):
    with pytest.raises(LabOnlyError, match="only lab hosts"):
        load_settings(_env(tmp_path, **{key: url}))


def test_allowed_hosts_can_be_set_for_another_lab(tmp_path):
    s = load_settings(
        _env(
            tmp_path,
            WAZUH_ALLOWED_HOSTS="lab2.local",
            WAZUH_API_URL="https://lab2.local:55000",
            WAZUH_INDEXER_URL="https://lab2.local:9200",
        )
    )
    assert s.api_url == "https://lab2.local:55000"


def test_missing_keys_error_names_keys_not_values(tmp_path):
    with pytest.raises(RuntimeError) as err:
        load_settings(_env(tmp_path, WAZUH_API_PASSWORD=None, WAZUH_INDEXER_CA=None))
    msg = str(err.value)
    assert "WAZUH_API_PASSWORD" in msg and "WAZUH_INDEXER_CA" in msg
    assert "idx-secret-value" not in msg


def test_repr_hides_passwords(tmp_path):
    text = repr(load_settings(_env(tmp_path)))
    assert "api-secret-value" not in text
    assert "idx-secret-value" not in text
