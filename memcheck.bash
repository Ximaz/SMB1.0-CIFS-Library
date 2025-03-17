#!/bin/bash
./compile.bash
valgrind --leak-check=full --track-origins=yes --read-var-info=yes --trace-children=yes --show-leak-kinds=all --read-inline-info=yes --errors-for-leak-kinds=all --expensive-definedness-checks=yes -s ./a.out