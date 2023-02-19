# -*- Makefile -*-

# Copyright (C) 2017-2023 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

SCRIPTS = \
 festival

SCRIPTS_IN = \
 bcc.in\
 bcc-version.in\
 bpp.in\
 bpp-version.in\
 dcc.in\
 dcc-version.in\
 fbc.in\
 fbc-version.in\
 fbc-32.in\
 fbc-32-version.in\
 fpc.in\
 fpc-version.in\
 fpc-32.in\
 fpc-32-version.in\
 g++.in\
 g++-version.in\
 g++-vg.in\
 g++-vg-version.in\
 g++-32.in\
 g++-32-version.in\
 g77.in\
 g77-version.in\
 gfortran.in\
 gfortran-version.in\
 gcc.in\
 gcc-version.in\
 gcc-vg.in\
 gcc-vg-version.in\
 gcc-32.in\
 gcc-32-version.in\
 gas-32.in\
 gas-32-version.in\
 gas.in\
 gas-version.in\
 gcj.in\
 gcj-version.in\
 gpc.in\
 gpc-version.in\
 gprolog.in\
 gprolog-version.in\
 kumir.in\
 kumir-version.in\
 kumir2.in\
 kumir2-version.in\
 mzscheme.in\
 mzscheme-version.in\
 nasm-x86.in\
 nasm-x86-version.in\
 node.in\
 node-version.in\
 qb.in\
 qb-version.in\
 perl.in\
 perl-version.in\
 php.in\
 php-version.in\
 python.in\
 python-version.in\
 python3.in\
 python3-version.in\
 pypy.in\
 pypy-version.in\
 pypy3.in\
 pypy3-version.in\
 ruby.in\
 ruby-version.in\
 rust.in\
 rust-version.in\
 tpc.in\
 tpc-version.in\
 yabasic.in\
 yabasic-version.in\
 javac.in\
 javac-version.in\
 javac7.in\
 javac7-version.in\
 scala.in\
 scala-version.in\
 kotlin.in\
 kotlin-version.in\
 mcs.in\
 mcs-version.in\
 vbnc.in\
 vbnc-version.in\
 make.in\
 make-version.in\
 make-vg.in\
 make-vg-version.in\
 ghc.in\
 ghc-version.in\
 clang.in\
 clang-version.in\
 clang-32.in\
 clang-32-version.in\
 clang++.in\
 clang++-version.in\
 clang++-32.in\
 clang++-32-version.in\
 gccgo.in\
 gccgo-version.in\
 pasabc-linux.in\
 pasabc-linux-version.in\
 mars.in\
 mars-version.in\
 rars.in\
 rars-version.in\
 dotnet-cs-version.in\
 dotnet-cs.in\
 dotnet-vb-version.in\
 dotnet-vb.in\
 swift-version.in\
 swift.in\
 custom-version.in\
 custom.in\
 runvg.in\
 runvg2.in\
 runjava.in\
 runjava2.in\
 runmono.in\
 runmono2.in\
 runperl.in\
 rundotnet.in\
 rundotnet2.in

POLICIES = \
 fileio.policy \
 default.policy
