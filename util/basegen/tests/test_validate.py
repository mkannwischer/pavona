# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
from jsonschema.exceptions import ValidationError
from referencing.jsonschema import SchemaRegistry, SchemaResource, DRAFT202012

from basegen.validate import validate_schema


NESTED_SCHEMAS = (
    {
        "$id": "urn:test_basegen:parent",
        "properties": {
            "my_child": {"$ref": "urn:test_basegen:child"}}},
    {
        "$id": "urn:test_basegen:child",
        "required": ["foo"],
        "properties": {
            "foo": {"type": "integer"}}}
)
GOOD_PARENTS = ({}, {"my_child": {"foo": 3}})
BAD_PARENTS = ({"my_child": {}},
               {"my_child": {"foo": "3"}})


def test_nested_schemas():
    parent, child = NESTED_SCHEMAS
    registry = SchemaRegistry().with_resources((
        (parent["$id"], SchemaResource(parent, DRAFT202012)),
        (child["$id"], SchemaResource(child, DRAFT202012))
    )).crawl()

    for good in GOOD_PARENTS:
        validate_schema(good, "urn:test_basegen:parent", registry=registry)
    for bad in BAD_PARENTS:
        try:
            validate_schema(bad, "urn:test_basegen:parent", registry=registry)
        except ValidationError:
            continue
        raise Exception("nested schema failed to catch bad dataset:"
                        f"\n\t{bad}")
