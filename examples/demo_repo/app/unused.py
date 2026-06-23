"""Imports requests + jinja2 but nothing ever calls these functions —
the vulnerable symbols are UNREACHABLE from any entrypoint.

This file exists to demonstrate that dependency presence != exploitability.
"""
import requests
from jinja2 import Template


def _never_called_fetch(url: str):
    return requests.get(url).text


def _never_called_render(src: str):
    return Template(src).render()
