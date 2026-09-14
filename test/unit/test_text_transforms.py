import base64

import pytest

from bashsim import text_transforms as tt


def test_echo_basic():
    assert tt.echo(["hello", "world"]) == "hello world\n"


def test_echo_no_newline():
    assert tt.echo(["hello"], no_newline=True) == "hello"


def test_printf_substitutes_percent_s():
    assert tt.printf("%s-%s", ["a", "b"]) == "a-b"


def test_base64_decode_roundtrip():
    original = "http://192.0.2.60/payload"
    encoded = base64.b64encode(original.encode()).decode()
    assert tt.base64_decode(encoded) == original


def test_base64_decode_invalid_raises():
    with pytest.raises(tt.TransformError):
        tt.base64_decode("not valid base64!!!")


def test_tr_translates_characters():
    assert tt.tr("abc", "abc", "xyz") == "xyz"


def test_rev_reverses_string():
    assert tt.rev("hello") == "olleh"


def test_xxd_r_plain_decodes_hex():
    assert tt.xxd_r("68656c6c6f", plain=True) == "hello"


def test_xxd_r_invalid_raises():
    with pytest.raises(tt.TransformError):
        tt.xxd_r("not hex at all!!", plain=True)
