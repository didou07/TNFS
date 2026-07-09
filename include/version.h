#ifndef VERSION_H
#define VERSION_H

#ifndef APP_VERSION
#error "APP_VERSION must be defined by the build system from the VERSION file"
#endif

#define APP_NAME    "TVCAS Newcamd Fake Stream"
#define APP_TITLE   APP_NAME " v" APP_VERSION

#endif
