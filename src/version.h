// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#include "clientversion.h"
#include <string>

//
// client versioning
//

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;

static const int PROTOCOL_VERSION = 60016;
static const int MIN_PROTOCOL_VERSION = 60016;

// earlier versions not supported as of Feb 2012, and are disconnected
static const int MIN_PROTO_VERSION = 209;

#define DISPLAY_VERSION_MAJOR       CLIENT_VERSION_MAJOR
#define DISPLAY_VERSION_MINOR       CLIENT_VERSION_MINOR
#define DISPLAY_VERSION_REVISION    CLIENT_VERSION_REVISION
#define DISPLAY_VERSION_BUILD       CLIENT_VERSION_BUILD

#endif
