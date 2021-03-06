TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -Wfatal-errors -pedantic-errors

SOURCES += \
    parser.c \
    rfc_structs.c \
    blacklist_loader.c \
    dnsfilterd.c \
    log.c

HEADERS += \
    rfc_structs.h \
    parser.h \
    blacklist_loader.h \
    log.h

DISTFILES +=
