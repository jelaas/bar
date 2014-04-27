#ifndef LOGCB_H
#define LOGCB_H

struct logcb {
  int (*pre)(void); /* start of line "bar: " */
  int (*post)(); /* end of line "\n" */
  int (*log)(const char *fmt, ...);
  int (*logln)(const char *fmt, ...); /* includes calls to pre and post */
  int level;
};

#endif
