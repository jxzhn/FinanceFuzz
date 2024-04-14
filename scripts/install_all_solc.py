#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import solcx

versions = solcx.get_installable_solc_versions()
for version in versions:
    print(f"Installing solc version {version}")
    solcx.install_solc(version)
