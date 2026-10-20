import os
import sys
from pathlib import Path

import pytest

from contract import contract_json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from generate_principal import GENERATED, generate


def test_the_principal_type_is_what_the_pinned_schema_generates() -> None:
    # PRINCIPAL_UPDATE=true task test
    want = generate(contract_json("principal.schema.json"))
    if os.environ.get("PRINCIPAL_UPDATE") == "true":
        GENERATED.write_text(want)

    assert GENERATED.read_text() == want


def test_the_principal_type_is_not_generated_for_a_shape_the_generator_does_not_know() -> None:
    with pytest.raises(ValueError, match="no Python type for n"):
        generate({"title": "T", "type": "object", "properties": {"n": {"type": "number"}}})
