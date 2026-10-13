# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Compiles Jasmin sources to ACC code; see //sw/acc/jasmin for an example."""

load("//rules:acc.bzl", "acc_library")

def jasmin_library(name, src, **kwargs):
    """Compiles a Jasmin source and assembles it into an `acc_library`.

    Args:
      name: The name of the `acc_library`.
      src: The Jasmin source.
      **kwargs: Passed on to `acc_library`.
    """

    native.genrule(
        name = name + "_asm",
        srcs = [src],
        outs = [name + "_asm.s"],
        cmd = "$(execpath @jasmin_acc//:bin/jasminc) -arch otbn $(location {}) -o $@".format(src),
        tools = ["@jasmin_acc//:bin/jasminc"],
        tags = kwargs.get("tags"),
    )
    acc_library(
        name = name,
        srcs = [name + "_asm.s"],
        **kwargs
    )
