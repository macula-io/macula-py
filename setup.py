"""The wheel carries macula-go's shared library (macula_py/_native/), loaded
with ctypes: it is tied to a platform but not to a CPython ABI, so it is
tagged py3-none-<platform> and one wheel serves every supported Python."""

import sys
from pathlib import Path

from setuptools import setup
from setuptools.dist import Distribution
from wheel.bdist_wheel import bdist_wheel


class PlatformWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def run(self):
        # A wheel without the library installs and then fails on first use;
        # refuse to build one.
        native = Path(__file__).parent / "src" / "macula_py" / "_native"
        names = {"linux": "libmacula.so", "darwin": "libmacula.dylib", "win32": "macula.dll"}
        name = names.get("linux" if sys.platform.startswith("linux") else sys.platform)
        if name is None or not (native / name).is_file():
            raise SystemExit(f"macula-py: {native / str(name)} is missing; build macula-go's cabi into it first")
        super().run()

    def get_tag(self):
        _, _, platform = super().get_tag()
        return "py3", "none", platform


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


setup(cmdclass={"bdist_wheel": PlatformWheel}, distclass=BinaryDistribution)
