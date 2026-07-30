import os
import subprocess
import tempfile
import unittest

import identity


class IdentityTests(unittest.TestCase):
    def test_generated_identity_is_locally_git_ignored(self):
        with tempfile.TemporaryDirectory() as repo:
            subprocess.run(["git", "init", "--quiet", repo], check=True)
            project = os.path.join(repo, "packages", "demo")
            os.makedirs(project)

            agent_id = identity.resolve_agent_id(project)

            self.assertTrue(agent_id.startswith("agent-"))
            self.assertTrue(os.path.isfile(os.path.join(project, ".antrozous", "identity.json")))
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(status.stdout, "")

            exclude_path = subprocess.run(
                ["git", "rev-parse", "--git-path", "info/exclude"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if not os.path.isabs(exclude_path):
                exclude_path = os.path.join(repo, exclude_path)
            with open(exclude_path, encoding="utf-8") as file:
                self.assertIn(".antrozous/", {line.strip() for line in file})


if __name__ == "__main__":
    unittest.main()
