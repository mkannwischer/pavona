# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_python//python:defs.bzl", "py_library")
load("@ot_python_deps//:requirements.bzl", "requirement")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "prim_mubi",
    srcs = [
        "src/mubi/__init__.py",
        "src/mubi/prim_mubi.py",
    ],
    imports = ["src"],
    deps = [requirement("mako")],
)
