#!/usr/bin/env python3
"""Regression tests for the shared native-build environment guard."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildSupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="ed301-build-support-")
        cls.probe = Path(cls.work.name) / "probe"
        cls.clean = {"PATH": "/usr/bin:/bin", "HOME": cls.work.name, "LC_ALL": "C"}
        subprocess.run(["rustc", "--edition=2024", "-Dwarnings",
                        ROOT / "provider-tests/build_support_probe.rs", "-o", cls.probe],
                       env=cls.clean, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def probe_result(self, command, expected, **extra):
        result = subprocess.run([self.probe, command], env=dict(self.clean, **extra),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode == 0, expected, result.stderr.decode(errors="replace"))

    def test_native_overrides(self):
        self.probe_result("reject", True, CC="/usr/bin/gcc", AR="/usr/bin/ar", CCACHE_DISABLE="1")
        names = ("ARFLAGS CFLAGS CCC_OVERRIDE_OPTIONS CCC_PRINT_BINDINGS CCC_PRINT_OPTIONS "
                 "COMPILER_PATH CPPFLAGS CXXFLAGS LDFLAGS LIBRARY_PATH CPATH C_INCLUDE_PATH "
                 "CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH CRATE_CC_NO_DEFAULTS CC_ENABLE_DEBUG_OUTPUT "
                 "GCC_EXEC_PREFIX HOST_ARFLAGS HOST_CFLAGS TARGET_ARFLAGS TARGET_CFLAGS").split()
        names += [prefix + "target" for prefix in
                  ("CC_", "CXX_", "AR_", "RANLIB_", "CFLAGS_", "CPPFLAGS_", "CXXFLAGS_", "LDFLAGS_")]
        for name in names:
            with self.subTest(name=name):
                self.probe_result("reject", False, **{name: ""})

    def test_exact_environment(self):
        self.probe_result("exact", True, PROBE_EXACT="1")
        self.probe_result("exact", False)
        self.probe_result("exact", False, PROBE_EXACT="0")

    def test_canonical_directory(self):
        self.probe_result("directory", True, PROBE_DIRECTORY=self.work.name)
        self.probe_result("directory", False)
        self.probe_result("directory", False, PROBE_DIRECTORY=str(self.probe))
        self.probe_result("directory", False, PROBE_DIRECTORY=self.work.name + "/missing")
        self.probe_result("directory", False, PROBE_DIRECTORY=self.work.name + "\n")
        odd = Path(self.work.name) / "with\nnewline"
        odd.mkdir()
        alias = Path(self.work.name) / "alias"
        alias.symlink_to(odd)
        self.probe_result("directory", False, PROBE_DIRECTORY=str(alias))


if __name__ == "__main__":
    unittest.main()
