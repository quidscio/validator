"""Setuptools build hooks that record the build time once per artifact."""
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from setuptools import build_meta as _setuptools


def _stamp_build() -> None:
    timestamp = datetime.now(ZoneInfo("America/New_York")).strftime("%Y-%m-%d_%H:%M")
    metadata = Path(__file__).with_name("smtp_probe_build.py")
    metadata.write_text(
        '"""Generated at package build time; do not edit manually."""\n'
        f'BUILD_TIMESTAMP = "{timestamp}"\n'
        'BUILD_TIMEZONE = "America/New_York"\n',
        encoding="utf-8",
    )


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _stamp_build()
    return _setuptools.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _stamp_build()
    return _setuptools.build_editable(wheel_directory, config_settings, metadata_directory)


def build_sdist(sdist_directory, config_settings=None):
    _stamp_build()
    return _setuptools.build_sdist(sdist_directory, config_settings)


get_requires_for_build_wheel = _setuptools.get_requires_for_build_wheel
get_requires_for_build_editable = _setuptools.get_requires_for_build_editable
get_requires_for_build_sdist = _setuptools.get_requires_for_build_sdist
prepare_metadata_for_build_wheel = _setuptools.prepare_metadata_for_build_wheel
prepare_metadata_for_build_editable = _setuptools.prepare_metadata_for_build_editable
