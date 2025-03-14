/// File: Interface to the RCBF/RDBF parser
///
/// Copyright (C) Microsoft Corporation
/// SPDX-License-Identifier: MIT

#ifndef PARSER_H
#define PARSER_H

#include "rcbf.h"
#include "rdbf.h"

rcbf_t *parse_rcbf(const char *filename);
void free_rcbf(rcbf_t *rcbf);

rdbf_t *parse_rdbf(const char *filename);
void free_rdbf(rdbf_t *rdbf);

#endif // PARSER_H
