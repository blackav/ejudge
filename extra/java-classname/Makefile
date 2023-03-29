# -*- Makefile -*-

# Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

JAVAC = javac
JAR = jar

all : java-classname.jar

java-classname.jar : JavaClassNameExtractor.class
	$(JAR) -c -v -f java-classname.jar -e JavaClassNameExtractor $^

JavaClassNameExtractor.class : JavaClassNameExtractor.java
	$(JAVAC) --release 11 $^

clean :
	-rm -f *.class *.jar
