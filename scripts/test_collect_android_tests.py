"""Regression checks for exporting target tests and launching host macro tests."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("collect_android_tests.py")

class CollectAndroidTests(unittest.TestCase):
    def run_collector(self, host_failure=False):
        with tempfile.TemporaryDirectory(prefix="omk-collect-tests-") as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(root.parent, Path(tempfile.gettempdir()).resolve())
            rustlib = root / "rustlib"
            rustlib.mkdir()
            events = []
            for name, machine, kind in [("macro", 62, "proc-macro"), ("android", 183, "lib")]:
                binary = root / name
                elf = bytearray(20)
                elf[:4] = b"\x7fELF"
                elf[18:20] = machine.to_bytes(2, "little")
                binary.write_bytes(elf)
                events.append({"reason": "compiler-artifact", "profile": {"test": True}, "executable": str(binary), "target": {"name": name, "kind": [kind]}})
            messages = root / "cargo.jsonl"
            messages.write_text("\n".join(json.dumps(event) for event in events))
            output = root / "output"
            with patch.object(sys, "argv", [str(SCRIPT), str(messages), str(output)]), patch.dict(os.environ, {"LD_LIBRARY_PATH": "existing-libraries"}), patch("subprocess.check_output", return_value=str(rustlib)) as locate, patch("subprocess.run") as execute:
                if host_failure:
                    execute.side_effect = subprocess.CalledProcessError(1, ["macro"])
                    with self.assertRaises(subprocess.CalledProcessError):
                        runpy.run_path(str(SCRIPT), run_name="__main__")
                    self.assertFalse((output / "manifest.json").exists())
                    return
                runpy.run_path(str(SCRIPT), run_name="__main__")
                locate.assert_called_once_with(["rustc", "--print", "target-libdir"], text=True)
                execute.assert_called_once()
                self.assertEqual(execute.call_args.args[0], [str(root / "macro")])
                self.assertTrue(execute.call_args.kwargs["check"])
                self.assertEqual(execute.call_args.kwargs["env"]["LD_LIBRARY_PATH"], os.pathsep.join([str(rustlib), "existing-libraries"]))
                self.assertEqual(os.environ["LD_LIBRARY_PATH"], "existing-libraries")
            android = json.loads((output / "manifest.json").read_text())
            host = json.loads((output / "host-tests.json").read_text())
            self.assertEqual([entry["target"] for entry in android], ["android"])
            self.assertEqual([entry["target"] for entry in host], ["macro"])
            self.assertEqual(android[0]["sha256"], hashlib.sha256((output / "android").read_bytes()).hexdigest())
            self.assertFalse((output / "macro").exists())

    def test_host_rust_libraries_are_available_without_exporting_host_binary(self):
        self.run_collector()

    def test_host_test_failure_still_fails_the_gate(self):
        self.run_collector(host_failure=True)

if __name__ == "__main__":
    unittest.main()
