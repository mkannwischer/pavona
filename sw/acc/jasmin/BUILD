# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//rules:acc.bzl", "acc_sim_test")
load("//rules:jasmin.bzl", "jasmin_library")

jasmin_library(
    name = "mul256",
    src = "mul256.jazz",
    tags = ["manual"],
)

acc_sim_test(
    name = "mul256_test",
    srcs = ["mul256_test.s"],
    exp = "mul256_test.exp",
    tags = ["manual"],
    deps = [":mul256"],
)
