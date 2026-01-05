#!/usr/bin/env python3

import argparse  # noqa: F401
import random
import re  # noqa: F401
import os
import socket
import ssl
import string
import sys
import time
import traceback  # noqa: F401
from urllib.parse import (
    urljoin,  # noqa: F401
    urlparse,
)

import requests
import urllib3
from bs4 import BeautifulSoup

import requests.utils

def _noop_check_header_validity(header, value=None):
    return None

requests.utils.check_header_validity = _noop_check_header_validity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils.cli import get_args

args = get_args()