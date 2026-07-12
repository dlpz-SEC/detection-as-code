"""
Keep pytest from collecting test_detections.py.

test_detections.py matches pytest's ``test_*.py`` pattern but is a standalone
CLI harness (its ``def test_rule(...)`` takes required positional args and its
``Test*`` dataclasses aren't test classes). ``pytest.ini`` restricts the
default run to ``tests/``, but an explicit ``pytest .`` / ``pytest scripts/``
would still try to collect this file - ``collect_ignore`` blocks that too.
"""

collect_ignore = ["test_detections.py"]
