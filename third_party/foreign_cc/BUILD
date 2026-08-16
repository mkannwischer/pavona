# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

# rules_foreign_cc bootstraps GNU Make from source by default, but its vendored
# `lib/glob.c` does not compile with clang 15 or newer, which promotes
# `-Wincompatible-pointer-types` to an error. Use the system `make` on macOS
# instead. Linux keeps the built-from-source toolchain.
toolchain(
    name = "preinstalled_make_toolchain_macos",
    exec_compatible_with = ["@platforms//os:macos"],
    toolchain = "@rules_foreign_cc//toolchains:preinstalled_make",
    toolchain_type = "@rules_foreign_cc//toolchains:make_toolchain",
)
