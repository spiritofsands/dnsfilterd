TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -Wfatal-errors -pedantic-errors

SOURCES += main.c \
    parser.c \
    rfc_structs.c \
    blacklist_loader.c \
    printAndExit.c

HEADERS += \
    rfc_structs.h \
    parser.h \
    blacklist_loader.h \
    printAndExit.h

DISTFILES +=
