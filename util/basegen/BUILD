# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_python//python:defs.bzl", "py_library")
load("@ot_python_deps//:requirements.bzl", "requirement")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "basegen",
    srcs = [
        "src/basegen/__init__.py",
        "src/basegen/lib.py",
        "src/basegen/typing.py",
        "src/basegen/validate.py",
    ],
    imports = ["src"],
    deps = [
        requirement("hjson"),
        requirement("jsonschema"),
        requirement("jsonschema2md"),
        requirement("referencing"),
    ],
)
