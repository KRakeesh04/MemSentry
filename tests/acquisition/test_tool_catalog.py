from memsentry.acquisition.config import load_environment_file
from memsentry.acquisition.tool_catalog import available_tools


def test_dotenv_relative_tool_is_discovered_on_matching_host(tmp_path, monkeypatch):
    monkeypatch.setattr("memsentry.acquisition.tool_catalog.platform.system", lambda: "Linux")
    monkeypatch.setattr("memsentry.acquisition.tool_catalog.which", lambda _: None)
    monkeypatch.delenv("MEMSENTRY_AVML", raising=False)
    tool = tmp_path / "avml"
    tool.write_bytes(b"test only")
    tool.chmod(0o700)
    env = tmp_path / ".env"
    env.write_text("MEMSENTRY_AVML=avml\n")
    load_environment_file(env)
    options = available_tools()
    assert options[0].available
    assert options[0].path == tool
    assert not options[1].available


def test_invalid_configured_path_does_not_silently_use_another_tool(tmp_path, monkeypatch):
    monkeypatch.setattr("memsentry.acquisition.tool_catalog.platform.system", lambda: "Linux")
    monkeypatch.setenv("MEMSENTRY_AVML", str(tmp_path / "missing"))
    monkeypatch.setattr("memsentry.acquisition.tool_catalog.which", lambda _: "/usr/bin/avml")
    assert not available_tools()[0].available
