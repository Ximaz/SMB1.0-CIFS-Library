# SMB 1.0 / CIFS Library

This repository aims to implement an SMB 1.0 / CIFS library, compliant to the
documents found on Microsoft Learn which are PDFs saved into [`./docs`](./docs).

The `smb_cifs.h` header file contains all the structures, enumerations and type
definitions, along with snippet of documentation.

## Purpose

The purpose of this repository is to create a small client that I can use on a
`Raspberry PI 1 B+`. I challenged myself to write my own, in C, and to use it
to communicate with my NAS, which is too old to support any other version of
SMB.

It's a learning project, you should not use it in production, not because I
don't want to, but rather because it may not be bulletproof, and I won't be
responsible for any issue it may cause to you, other, or devices.

## Buffer

The [./buffer/](./buffer/) directory contains the C implementation of a fixed-
size buffer that will be used to implement a client in the future.
