# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from typing import Any, Dict, Tuple

from jsonschema.exceptions import ValidationError

from basegen.lib import import_hjson
from reggen.validate import validate_schema

REPO_TOP = Path(__file__).resolve().parents[2]

KNOWN_GOOD_IPDESCS = {ipdesc
                      for ipdesc in (REPO_TOP / "hw/ip").glob("*/data/*.hjson")
                      if (ipdesc.stem == ipdesc.parents[1].name
                          and ipdesc.stem != "tlul")}  # tlul is not an IP
KNOWN_BAD_IPDESCS: Tuple[Dict[str, Any], ...] = ({}, {"name": "foo", "clocking": {}})


def test_ip_block_validation() -> None:
    for good in KNOWN_GOOD_IPDESCS:
        validate_schema(import_hjson(good), "urn:reggen:ip_block")
    for bad in KNOWN_BAD_IPDESCS:
        try:
            validate_schema(bad, "urn:reggen:ip_block")
        except ValidationError:
            continue
        raise Exception("IP block description validation incorrectly approved bad description!"
                        f"\n\t{bad}")
