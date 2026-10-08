# Copyright lowRISC contributors (OpenTitan project).
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_python//python:defs.bzl", "py_library")
load("@ot_python_deps//:requirements.bzl", "requirement")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "reggen",
    srcs = glob(["src/reggen/**/*.py"]),
    data = [
        ":tpl_files",
        "//util/reggen/src/reggen/schemas",
    ],
    imports = ["src"],
    deps = [
        "//util/basegen",
        "//util/design/mubi:prim_mubi",
        "//util/reggen/src/reggen/systemrdl:udp",
        "//util/version_file",
        requirement("hjson"),
        requirement("semantic_version"),
        requirement("mako"),
        requirement("pyyaml"),
        requirement("mistletoe"),
        requirement("peakrdl_systemrdl"),
        requirement("tabulate"),
    ],
)

py_library(
    name = "lib",
    srcs = [
        "src/reggen/__init__.py",
        "src/reggen/lib.py",
    ],
    imports = ["src"],
)

py_library(
    name = "access",
    srcs = ["src/reggen/access.py"],
    deps = [":lib"],
)

py_library(
    name = "alert",
    srcs = ["src/reggen/alert.py"],
    deps = [
        ":bits",
        ":lib",
        ":signal",
        ":validate",
    ],
)

py_library(
    name = "bits",
    srcs = ["src/reggen/bits.py"],
    deps = [
        ":lib",
        ":params",
    ],
)

py_library(
    name = "bus_interfaces",
    srcs = ["src/reggen/bus_interfaces.py"],
    deps = [
        ":inter_signal",
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "clocking",
    srcs = ["src/reggen/clocking.py"],
    deps = [
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "countermeasure",
    srcs = ["src/reggen/countermeasure.py"],
    deps = [
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "feature",
    srcs = ["src/reggen/feature.py"],
    deps = [
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "enum_entry",
    srcs = ["src/reggen/enum_entry.py"],
    deps = [
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "field",
    srcs = ["src/reggen/field.py"],
    deps = [
        ":access",
        ":bits",
        ":enum_entry",
        ":lib",
        ":params",
        ":validate",
        "//util/design/mubi:prim_mubi",
    ],
)

py_library(
    name = "interrupt",
    srcs = ["src/reggen/interrupt.py"],
    deps = [
        ":access",
        ":bits",
        ":lib",
        ":signal",
        ":validate",
    ],
)

py_library(
    name = "html_helpers",
    srcs = ["src/reggen/html_helpers.py"],
)

py_library(
    name = "inter_signal",
    srcs = ["src/reggen/inter_signal.py"],
    deps = [
        ":lib",
        ":params",
        ":validate",
    ],
)

py_library(
    name = "ip_block",
    srcs = ["src/reggen/ip_block.py"],
    deps = [
        ":alert",
        ":bus_interfaces",
        ":clocking",
        ":countermeasure",
        ":feature",
        ":inter_signal",
        ":interrupt",
        ":lib",
        ":memory",
        ":params",
        ":reg_block",
        ":signal",
        ":validate",
        requirement("hjson"),
        requirement("semantic_version"),
    ],
)

py_library(
    name = "params",
    srcs = ["src/reggen/params.py"],
    deps = [
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "reg_base",
    srcs = ["src/reggen/reg_base.py"],
    deps = [
        ":clocking",
        ":field",
    ],
)

py_library(
    name = "reg_block",
    srcs = ["src/reggen/reg_block.py"],
    deps = [
        ":access",
        ":alert",
        ":bus_interfaces",
        ":clocking",
        ":field",
        ":interrupt",
        ":lib",
        ":memory",
        ":multi_register",
        ":params",
        ":register",
        ":signal",
        ":window",
        requirement("semantic_version"),
    ],
)

py_library(
    name = "register",
    srcs = ["src/reggen/register.py"],
    deps = [
        ":access",
        ":clocking",
        ":field",
        ":lib",
        ":params",
        ":reg_base",
        ":validate",
        "//util/design/mubi:prim_mubi",
    ],
)

py_library(
    name = "multi_register",
    srcs = ["src/reggen/multi_register.py"],
    deps = [
        ":clocking",
        ":field",
        ":lib",
        ":params",
        ":reg_base",
        ":register",
        ":validate",
    ],
)

py_library(
    name = "signal",
    srcs = ["src/reggen/signal.py"],
    deps = [
        ":bits",
        ":lib",
        ":validate",
    ],
)

py_library(
    name = "memory",
    srcs = ["src/reggen/memory.py"],
    deps = [
        ":access",
        ":lib",
        ":params",
        ":window",
    ],
)

py_library(
    name = "window",
    srcs = ["src/reggen/window.py"],
    deps = [
        ":access",
        ":lib",
        ":params",
        ":validate",
    ],
)

py_library(
    name = "gen_cheader",
    srcs = ["src/reggen/gen_cheader.py"],
    deps = [
        ":field",
        ":ip_block",
        ":multi_register",
        ":params",
        ":register",
        ":signal",
        ":window",
    ],
)

py_library(
    name = "gen_dv",
    srcs = ["src/reggen/gen_dv.py"],
    data = [":tpl_files"],
    deps = [
        ":ip_block",
        ":multi_register",
        ":register",
        ":window",
        requirement("mako"),
        requirement("pyyaml"),
    ],
)

py_library(
    name = "gen_fpv",
    srcs = ["src/reggen/gen_fpv.py"],
    data = [":tpl_files"],
    deps = [
        ":ip_block",
        requirement("mako"),
        requirement("pyyaml"),
    ],
)

py_library(
    name = "gen_html",
    srcs = ["src/reggen/gen_html.py"],
    deps = [
        ":html_helpers",
        ":ip_block",
        ":multi_register",
        ":reg_block",
        ":register",
        ":window",
        requirement("mistletoe"),
    ],
)

py_library(
    name = "gen_md",
    srcs = ["src/reggen/gen_md.py"],
    deps = [
        ":ip_block",
        ":md_helpers",
        ":multi_register",
        ":reg_block",
        ":register",
        ":window",
    ],
)

py_library(
    name = "gen_cfg_md",
    srcs = ["src/reggen/gen_cfg_md.py"],
    deps = [
        ":ip_block",
        ":md_helpers",
        ":params",
    ],
)

py_library(
    name = "gen_json",
    srcs = ["src/reggen/gen_json.py"],
    deps = [requirement("hjson")],
)

py_library(
    name = "gen_rtl",
    srcs = ["src/reggen/gen_rtl.py"],
    data = [":tpl_files"],
    deps = [
        ":ip_block",
        ":lib",
        ":multi_register",
        ":reg_base",
        ":register",
        "//util/basegen",
        requirement("mako"),
    ],
)

py_library(
    name = "gen_rust",
    srcs = ["src/reggen/gen_rust.py"],
    deps = [
        ":field",
        ":ip_block",
        ":multi_register",
        ":params",
        ":register",
        ":signal",
        ":window",
    ],
)

py_library(
    name = "gen_tock",
    srcs = ["src/reggen/gen_tock.py"],
    deps = [
        ":field",
        ":ip_block",
        ":multi_register",
        ":params",
        ":register",
        ":signal",
        ":window",
        "//util/version_file",
    ],
)

py_library(
    name = "gen_sec_cm_testplan",
    srcs = ["src/reggen/gen_sec_cm_testplan.py"],
    data = [":tpl_files"],
    deps = [
        ":ip_block",
        requirement("hjson"),
        requirement("mako"),
    ],
)

py_library(
    name = "gen_selfdoc",
    srcs = ["src/reggen/gen_selfdoc.py"],
    deps = [
        ":access",
        ":enum_entry",
        ":field",
        ":ip_block",
        ":lib",
        ":multi_register",
        ":register",
        ":validate",
        ":window",
    ],
)

py_library(
    name = "exporter",
    srcs = ["src/reggen/exporter.py"],
    deps = [
        ":ip_block",
    ],
)

py_library(
    name = "systemrdl_exporter",
    srcs = ["src/reggen/systemrdl_exporter.py"],
    deps = [
        ":access",
        ":exporter",
        ":field",
        ":ip_block",
        ":multi_register",
        ":reg_block",
        ":register",
        ":window",
        "//util/reggen/src/reggen/systemrdl:udp",
        requirement("peakrdl_systemrdl"),
    ],
)

py_library(
    name = "md_helpers",
    srcs = ["src/reggen/md_helpers.py"],
    deps = [
        ":signal",
        requirement("tabulate"),
    ],
)

py_library(
    name = "validate",
    srcs = ["src/reggen/validate.py"],
    data = ["//util/reggen/src/reggen/schemas"],
    deps = [
        "//util/basegen",
        requirement("jsonschema"),
        requirement("jsonschema2md"),
        requirement("referencing"),
    ],
)

py_library(
    name = "version",
    srcs = ["src/reggen/version.py"],
)

filegroup(
    name = "tpl_files",
    srcs = glob(["**/*.tpl"]),
)

filegroup(
    name = "doc_files",
    srcs = glob([
        "**/*.md",
        "**/*.svg",
    ]),
)
