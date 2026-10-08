# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

from jsonschema.exceptions import ValidationError

from basegen.lib import import_hjson
from basegen.validate import validate_schema
from topgen.validate import SCHEMA_REGISTRY, TOPCFG_VALIDATOR

REPO_TOP = Path(__file__).resolve().parents[2]

KNOWN_GOOD_TOPCFGS = (
    REPO_TOP / "hw" / "top_dragonfly" / "data" / "top_dragonfly.hjson",
    REPO_TOP / "hw" / "top_egret" / "data" / "top_egret.hjson"
)
KNOWN_BAD_TOPCFGS = ({}, {"foo": 2})


def test_topcfg_validation():
    for good in KNOWN_GOOD_TOPCFGS:
        validate_schema(import_hjson(good), "urn:topgen:topcfg", registry=SCHEMA_REGISTRY)
        TOPCFG_VALIDATOR.validate(import_hjson(good))
    for bad in KNOWN_BAD_TOPCFGS:
        try:
            validate_schema(bad, "urn:topgen:topcfg", registry=SCHEMA_REGISTRY)
        except ValidationError:
            continue
        raise Exception("top config validation (direct) incorrectly approved bad config!"
                        f"\n\t{bad}")
