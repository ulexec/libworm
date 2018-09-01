//
// Created by ulexec on 16/08/18.
//
#include "elfw.h"

#ifndef LIBX_INJECT_H
#define LIBX_INJECT_H

#include <stdbool.h>

#define DEFAULT_PADDING 0x1000
int inject_data_segment(Elfw_Bin *, void *, Elfw_Bin **, bool, int *);
int inject_text_segment(Elfw_Bin *, void *, Elfw_Bin **, bool, int *);
#endif //LIBX_INJECT_H
