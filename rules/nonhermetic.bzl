# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

NONHERMETIC_ENV_VARS = [
    "XILINX_VIVADO",
    "XILINXD_LICENSE_FILE",
]

# Where macOS finds libelf, outside the compiler's default search paths.
MACOS_SEARCH_PATH_VARS = [
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "LIBRARY_PATH",
]

# Binarys that Bazel rule may depend on from the PATH.
NONHERMETIC_BINS = [
    "vivado",
    "updatemem",
]

"""Variables that describe non-hermetic parts of the environment.

This repository provides 5 variables:
    - `ENV`
        - Dict of environment variables that may be needed for running non-hermetic tools.
          Currently this only include those needed by Vivado.
    - `IS_MACOS`
        - Whether Bazel is running on a macOS host.
    - `MACOS_SEARCH_PATHS`
        - Header and library search paths for the system libraries that macOS
          keeps outside the compiler's defaults. Empty on every other host.
    - `HOME`
        - Home directory of the user that invokes Bazel.
          Currently this is used by hsmtool to access user's Google Cloud credentials.
    - `BIN_PATHS`
        - Map from a non-hermetic tool to the part of `$PATH` that contains it.
          This allows actions to use a subset of `$PATH` when invoking the tool,
          as `$PATH` may contain many unrelated tools.

Together, these variables attempt to expose the least amount of environment information
to Bazel rules as possible, thus improves reproducibility and cacheability.
"""

def _dict_entries(rctx, names):
    return "\n".join(["    \"{}\": \"{}\",".format(v, rctx.getenv(v, "")) for v in names])

def _nonhermetic_repo_impl(rctx):
    env = _dict_entries(rctx, NONHERMETIC_ENV_VARS)
    is_macos = rctx.os.name == "mac os x"
    if is_macos:
        search_paths = _dict_entries(rctx, MACOS_SEARCH_PATH_VARS)
    else:
        search_paths = ""
    home = rctx.getenv("HOME", "")

    # Declare sensitivity on PATH, this is not implied by `rctx.which`
    path = rctx.getenv("PATH")
    bins = {name: rctx.which(name) for name in NONHERMETIC_BINS}
    bin_paths = "\n".join(["    \"{}\": \"{}\",".format(name, rctx.path(path).dirname if path != None else "/no-such-path") for name, path in bins.items()])

    rctx.file("env.bzl", "ENV = {{\n{}\n}}\nIS_MACOS = {}\nMACOS_SEARCH_PATHS = {{\n{}\n}}\nHOME = \"{}\"\nBIN_PATHS = {{\n{}\n}}\n".format(env, is_macos, search_paths, home, bin_paths))
    rctx.file("BUILD.bazel", "exports_files(glob([\"**\"]))\n")

nonhermetic_repo = repository_rule(
    implementation = _nonhermetic_repo_impl,
    attrs = {},
)
