#!/usr/bin/env python

import os
from setuptools import setup, find_packages
from setuptools.discovery import find_package_path
import toml

# Read version from Cargo.toml
cargo_toml_path = os.path.join(os.path.dirname(__file__), '..', 'Cargo.toml')
cargo_toml = toml.load(cargo_toml_path)
version = cargo_toml['package']['version']

LONG_DESCRIPTION = """# payjoin
This repository creates libraries for various programming languages, all using the Rust-based [Payjoin](https://github.com/payjoin/rust-payjoin) 
as the core implementation of BIP178, sourced from the [Payjoin Dev Kit](https://payjoindevkit.org/).

## Install the package
```shell
pip install payjoin
```

## Usage 
```python
import payjoin as payjoin
"""

setup(
    name="payjoin",
    description="The Python language bindings for the Payjoin Dev Kit",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    include_package_data=True,
    zip_safe=False,
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    version=version,
    license="MIT or Apache 2.0",
    has_ext_modules=lambda: True,
)
