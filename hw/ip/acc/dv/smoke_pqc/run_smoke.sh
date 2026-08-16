#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Runs the ACC smoke test (builds software, build simulation, runs simulation
# and checks expected output)

fail() {
    echo >&2 "ACC SMOKE FAILURE: $*"
    exit 1
}

set -o pipefail
set -e

# `readlink -e` is GNU-only, so canonicalize with `cd`/`pwd -P` instead.
abs_dir() { (cd "$1" >/dev/null && pwd -P); }

SCRIPT_DIR="$(abs_dir "$(dirname "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(abs_dir "$SCRIPT_DIR/../../../../..")" || \
  fail "Can't find repository root dir"
UTIL_DIR="$(abs_dir "$ROOT_DIR/util")" || \
  fail "Can't find repository util dir"

source "$UTIL_DIR/build_consts.sh"

SMOKE_SRC_DIR=$ROOT_DIR/hw/ip/acc/dv/smoke_pqc

./bazelisk.sh build \
  //hw/ip/acc/dv/smoke_pqc:verilator_acc \
  //hw/ip/acc/dv/smoke_pqc:smoke_test_nondeterministic
SIM_BINARY=$(./bazelisk.sh cquery --output=files //hw/ip/acc/dv/smoke_pqc:verilator_acc)
SMOKE_ELF=$(./bazelisk.sh cquery --output=files //hw/ip/acc/dv/smoke_pqc:smoke_test_nondeterministic | grep "\\.elf$" | head -1)

RUN_LOG=`mktemp`
readonly RUN_LOG
# shellcheck disable=SC2064 # The RUN_LOG tempfile path should not change
trap "rm -rf $RUN_LOG" EXIT

timeout 5s ${SIM_BINARY} --load-elf=${SMOKE_ELF} -t | tee $RUN_LOG

if [ $? -eq 124 ]; then
  fail "Simulation timeout"
fi

if [ $? -ne 0 ]; then
  fail "Simulator run failed"
fi

had_diff=0
grep -A 74 "Call Stack:" $RUN_LOG | diff -U3 $SMOKE_SRC_DIR/smoke_expected.txt - || had_diff=1

if [ $had_diff == 0 ]; then
  echo "ACC SMOKE PASS"
else
  fail "Simulator output does not match expected output"
fi
