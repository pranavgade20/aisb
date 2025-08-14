from setuptools import setup, find_packages

setup(
    name="flower-power",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'flower-power=flower_power:main',
        ],
    },
)
