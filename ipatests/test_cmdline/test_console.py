#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
import inspect
import io
import pydoc

import pytest
import textwrap

from ipalib import api


@pytest.fixture()
def api_obj():
    if not api.Backend.rpcclient.isconnected():
        api.Backend.rpcclient.connect()
    yield api


@pytest.mark.tier0
@pytest.mark.needs_ipaapi
class TestIPAConsole:
    def run_pydoc(self, plugin):
        s = io.StringIO()
        # help() calls pydoc.doc() with pager
        pydoc.doc(plugin, "Help %s", output=s)
        return s.getvalue()

    def test_dir(self, api_obj):
        assert "Command" in dir(api_obj)
        assert "group_add" in dir(api_obj.Command)

    def test_signature(self, api_obj):
        sig = api_obj.Command.group_add.__signature__
        assert isinstance(sig, inspect.Signature)
        params = sig.parameters
        assert params['cn'].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert params['cn'].annotation is str
        assert params['description'].kind is inspect.Parameter.KEYWORD_ONLY

    def test_help(self, api_obj):
        s = self.run_pydoc(api_obj.Command.group_add)
        # check for __signature__ in help()
        snippets = [
            textwrap.dedent(
                """|  group_add(
                   |      cn: str,
                   |      *,
                   |      description: str = None,"""
            ),
            "group_add(cn: str, *, description: str = None,"
        ]

        present = [snippet in s for snippet in snippets]
        assert any(present)
