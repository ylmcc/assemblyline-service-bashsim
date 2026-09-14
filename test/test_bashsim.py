"""End-to-end TestHelper-based test. Network is fully mocked via requests_mock and DNS
resolution is fully mocked via unittest.mock.patch("socket.getaddrinfo") -- this test
never makes a real network/DNS call, never invokes real bash, and the sample fixture
(test/samples/*.cart) is a small synthetic shell script, not real malware.
"""
import os
import socket
from unittest.mock import patch

import pytest
import requests_mock as rm_module
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

service_class = load_module_by_path(
    "bashsim.bashsim.BashSim", os.path.join(os.path.dirname(__file__), "..")
)
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)


def _fake_getaddrinfo(host, *args, **kwargs):
    # The synthetic fixture's only hostname resolves to this ordinary, non-reserved
    # placeholder address (see test/unit/test_fetcher.py for why this address
    # specifically, rather than an RFC 5737 range, is used for "should succeed").
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]


@pytest.mark.parametrize("sample", th.result_list())
@patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo)
def test_sample(mock_getaddrinfo, sample):
    with rm_module.Mocker() as m:
        m.get(
            "http://payload.test/x.x86",
            content=b"fake payload x86",
            headers={"Content-Type": "application/octet-stream"},
        )
        m.get(
            "http://payload.test/x.arm",
            content=b"fake payload arm",
            headers={"Content-Type": "application/octet-stream"},
        )
        th.run_test_comparison(sample)
