#!/bin/bash
docker run -it --rm --volume .:/usr/app ximaz/epitest-docker-aarch64 ./memcheck.bash
