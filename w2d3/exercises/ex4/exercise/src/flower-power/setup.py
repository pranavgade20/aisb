from setuptools import setup, find_packages

setup(
    name="flower_power",
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