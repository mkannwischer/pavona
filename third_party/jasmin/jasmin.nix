# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

{ pkgs ? import <nixpkgs> { } }:

pkgs.jasmin-compiler.overrideAttrs {
  version = "0-unstable-2026-10-12";

  src = pkgs.fetchFromGitHub {
    owner = "sarranz";
    repo = "jasmin";
    rev = "794216c3862bc8e9e931a46e134bc186cd8ff574";
    hash = "sha256-4z/P/2EJglok1U9FlnbzeLyAqarB+lG50dBTzUuWDG8=";
  };

  postUnpack = ''
    tar xzf $sourceRoot/jasmin.tar.gz
    cp -r $sourceRoot/compiler/uint63 $sourceRoot/compiler/linter jasmin/compiler/
    chmod -R u+w jasmin
    sourceRoot=jasmin/compiler
  '';

  patches = [ ./jasmin-acc.patch ];
  patchFlags = [ "-p2" ];

  postInstall = ''
    make -C ../eclib install
  '';
}
