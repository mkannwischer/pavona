# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

import jsonschema
from jsonschema.validators import Draft202012Validator
from referencing.jsonschema import SchemaRegistry, SchemaResource, DRAFT202012
from referencing import Resource
import jsonschema2md

import os
from pathlib import Path
from typing import Any, TextIO
from .lib import import_hjson


def build_registry(*schema_dirs: str | os.PathLike[str]) -> SchemaRegistry:
    """Build a schema registry from every .hjson under the given directories."""
    schemas = [import_hjson(hj) for sd in schema_dirs for hj in Path(sd).rglob("*.hjson")]
    return SchemaRegistry().with_resources(
        (s["$id"], DRAFT202012.create_resource(s)) for s in schemas).crawl()


def _resolve_schema(schema: dict[str, Any] | str | SchemaResource,
                    registry: SchemaRegistry) -> dict[str, Any]:
    """Flexibly get the correct schema from a dict, URN string, or SchemaResource. If the schema
    is a string, search the registry for that URN.
    """
    # cast schema as dict for the jsonschema.validate function
    if isinstance(schema, str):
        schema = registry[schema]  # Resource
    if isinstance(schema, Resource):
        schema = schema.contents
    return schema


def validate_schema(data: dict[str, Any], schema: dict[str, Any] | str | Resource, *,
                    registry: SchemaRegistry) -> None:
    """Validate some data against a given schema."""
    schema = _resolve_schema(schema, registry)
    jsonschema.validate(data, schema, registry=registry)


def create_validator(schema: dict[str, Any] | str | Resource, *,
                     registry: SchemaRegistry) -> Draft202012Validator:
    """Create a Validator object for validating schemas (metaschema 2020-12)."""
    schema = _resolve_schema(schema, registry)
    return Draft202012Validator(schema, registry=registry)


def document_schema(outfile: TextIO | None,
                    schema: dict[str, Any] | str | Resource,
                    schema_parser: jsonschema2md.Parser = jsonschema2md.Parser(header_level=2), *,
                    registry: SchemaRegistry) -> str | None:
    """Document the requirements of a given schema in Markdown formatting.

    Output can either be directly written to text or returned as str. Schema documentation may be
    particularly useful for documenting the input file requirements for specific tools.
    """
    schema = _resolve_schema(schema, registry)
    schema_desc = schema_parser.parse_schema(schema)
    doc_text = "".join(schema_desc)

    if outfile is None:
        return doc_text
    else:
        outfile.write(doc_text)
    return None
