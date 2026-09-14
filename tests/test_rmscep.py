"""Package level tests"""

from rmscep import __version__


def test_version() -> None:
    """Make sure version matches expected"""
    assert __version__ == "1.0.1+260914"
