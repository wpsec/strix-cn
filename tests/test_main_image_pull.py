"""Tests for docker image selection hints in the CLI entrypoint."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

main = importlib.import_module("strix.interface.main")


def test_local_sandbox_build_tag_detects_local_strix_image() -> None:
    assert main._local_sandbox_build_tag("strix-sandbox:burp-split") == "burp-split"
    assert main._local_sandbox_build_tag("strix-sandbox") == "dev"
    assert main._local_sandbox_build_tag("ghcr.io/usestrix/strix-sandbox:1.0.0") is None


def test_pull_docker_image_fails_fast_with_local_build_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    printed: list[object] = []

    class _FakeConsole:
        def print(self, *args: object) -> None:
            printed.extend(args)

        def status(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("should not try pulling a missing local image")

    monkeypatch.setattr(main, "Console", lambda: _FakeConsole())
    monkeypatch.setattr(main, "Panel", lambda content, **_kwargs: content)
    monkeypatch.setattr(main, "check_docker_connection", lambda: object())
    monkeypatch.setattr(main, "image_exists", lambda *_args: False)
    monkeypatch.setattr(
        main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(image="strix-sandbox:burp-split")),
    )

    with pytest.raises(SystemExit) as exc:
        main.pull_docker_image()

    assert exc.value.code == 1
    plain = "".join(
        item.plain if hasattr(item, "plain") else str(item)
        for item in printed
    )
    assert "本地镜像未找到" in plain
    assert "./scripts/docker-overlay.sh burp-split" in plain
    assert "./scripts/docker.sh burp-split" in plain
    assert "ghcr.io/usestrix/strix-sandbox:1.0.0" in plain
