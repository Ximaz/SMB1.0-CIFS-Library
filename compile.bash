#!/bin/bash
cc -g -O0 main.c debug_memory/debug_memory.c smb_cifs.c commands/*.c
