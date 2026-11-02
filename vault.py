#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure Password Vault (CLI) - v3.4.0

Zero-trust, local-first encrypted password and credentials manager.
"""
from __future__ import annotations

import sys

from vault import *
from vault.cli import main

if __name__ == "__main__":
    sys.exit(main())
