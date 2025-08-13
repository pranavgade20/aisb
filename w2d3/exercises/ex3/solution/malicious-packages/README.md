This directory contains five typo-squatted packages (`alower_power`, `blower_power`, `clower_power`, `dlower_power`, `elower_power`).

Each package uses a custom `install` command to overwrite `/app/templates/index.html` when installed inside the developer/web containers. The original file is saved as `/app/templates/index.html.bak`.

Build all packages and copy the tarballs to the exercise's PyPI packages folder:

```sh
for p in a b c d e; do (cd ${p}lower_power && python3 setup.py sdist); done
mkdir -p ../../exercise/packages
for p in a b c d e; do cp ${p}lower_power/dist/*.tar.gz ../../exercise/packages/; done
```


