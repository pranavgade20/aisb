from setuptools import setup, find_packages
import sys
from setuptools.command.install import install

print("clown clown clown")

setup(
    name="test3",
    version="1.0.6",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'flower-power=alower_power:main',
        ],
    },
)
