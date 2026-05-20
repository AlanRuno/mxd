#!/bin/bash

set -e

# Detect operating system and MSYS2 environment
case "$(uname -s)" in
    Linux*)     
        ./install_dependencies_linux.sh "$@"
        ;;
    Darwin*)    
        ./install_dependencies_macos.sh "$@"
        ;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*)
        if [[ -n "$MSYSTEM" ]]; then
            ./install_dependencies_windows.sh "$@"
        else
            echo "Error: Please run this script from MSYS2 MinGW64 shell"
            exit 1
        fi
        ;;
    *)
        echo "Unsupported operating system"
        exit 1
        ;;
esac
