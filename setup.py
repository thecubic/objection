#!/usr/bin/env python

from distutils.core import setup

setup(
    name="objection",
    version="1.0",
    description="AndroidAPS preference editor",
    author="Dave Carlson",
    author_email="thecubic@thecubic.net",
    url="https://github.com/thecubic/objection/",
    packages=["objection"],
    scripts=["objection-dump", "objection-pass", "objection-reset", "objection-pwchg", "objection-reset"],
)
