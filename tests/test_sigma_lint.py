"""
Tests for scripts/sigma_lint.py - offline, no pySigma needed.

Pins the ATT&CK data contract: the bundle is versioned, hash-verified, and
downloaded at most once. pySigma itself is imported only inside main(), so the
unit-test job (which does not install the Sigma toolchain) can load this.
"""

import hashlib

import pytest

import sigma_lint


def _pin(monkeypatch, content: bytes):
    monkeypatch.setattr(sigma_lint, "ATTACK_SHA256", hashlib.sha256(content).hexdigest())


def test_url_names_the_pinned_version():
    """The URL must point at a versioned release file, never the moving master copy."""
    assert sigma_lint.ATTACK_URL.endswith(f"enterprise-attack-{sigma_lint.ATTACK_VERSION}.json")


def test_cached_verified_bundle_is_reused_without_download(tmp_path, monkeypatch):
    content = b'{"objects": []}'
    _pin(monkeypatch, content)
    cached = tmp_path / f"enterprise-attack-{sigma_lint.ATTACK_VERSION}.json"
    cached.write_bytes(content)

    def no_network(*_args, **_kwargs):
        raise AssertionError("must not download when a verified copy exists")

    monkeypatch.setattr(sigma_lint, "urlretrieve", no_network)
    assert sigma_lint.pinned_attack_file(tmp_path) == cached


def test_missing_bundle_is_downloaded_then_verified(tmp_path, monkeypatch):
    content = b'{"objects": [1]}'
    _pin(monkeypatch, content)
    calls = []

    def fake_urlretrieve(url, dest):
        calls.append(url)
        dest.write_bytes(content)

    monkeypatch.setattr(sigma_lint, "urlretrieve", fake_urlretrieve)
    path = sigma_lint.pinned_attack_file(tmp_path / "cache")
    assert calls == [sigma_lint.ATTACK_URL]
    assert path.read_bytes() == content
    assert not list(path.parent.glob("*.part"))  # partial file renamed into place


def test_hash_mismatch_is_fatal(tmp_path, monkeypatch):
    _pin(monkeypatch, b"the bundle we pinned")
    (tmp_path / f"enterprise-attack-{sigma_lint.ATTACK_VERSION}.json").write_bytes(b"something else")
    with pytest.raises(RuntimeError, match="SHA-256"):
        sigma_lint.pinned_attack_file(tmp_path)


def test_main_requires_a_path():
    with pytest.raises(SystemExit):
        sigma_lint.main([])
