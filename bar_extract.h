#ifndef BAR_EXTRACT_H
#define BAR_EXTRACT_H

#include "logcb.h"
#include "jelist.h"

int bar_extract(const struct logcb *log, const char *archive, struct jlhead *files, int *err, const struct bar_options *opt);

#endif
