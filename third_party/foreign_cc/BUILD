# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

# The GNU Make that rules_foreign_cc builds does not compile with clang 15+.
toolchain(
    name = "preinstalled_make_toolchain_macos",
    exec_compatible_with = ["@platforms//os:macos"],
    toolchain = "@rules_foreign_cc//toolchains:preinstalled_make",
    toolchain_type = "@rules_foreign_cc//toolchains:make_toolchain",
)
