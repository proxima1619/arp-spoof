QT -= gui
CONFIG += console c++11
CONFIG -= app_bundle
TEMPLATE = app
TARGET = arp-spoof

SOURCES += \
    arp-spoof.cpp \
    arphdr.cpp \
    ethhdr.cpp \
    ip.cpp \
    mac.cpp

HEADERS += \
    arphdr.h \
    ethhdr.h \
    ip.h \
    mac.h
