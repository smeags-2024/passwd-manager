#!/bin/bash

# Password Manager Launcher Script
# This script suppresses Qt debug output for a cleaner experience

# Set Qt environment variables to suppress debug output
export QT_LOGGING_RULES="*.debug=false;qt.qpa.xcb.debug=false;qt6ct.debug=false"
export QT_QPA_PLATFORMTHEME=""

# Run the password manager
password-manager "$@"
