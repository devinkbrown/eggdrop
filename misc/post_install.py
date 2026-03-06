#!/usr/bin/env python3
"""Post-install script for eggdrop.

Called by meson after installation:
  meson.add_install_script('misc/post_install.py', get_option('prefix'), get_option('datadir'))
"""

import os
import sys


def main():
    if len(sys.argv) < 3:
        print("Usage: post_install.py <prefix> <datadir>")
        sys.exit(1)

    prefix = sys.argv[1]
    datadir = sys.argv[2]

    # datadir may be relative (e.g. 'share'); make it absolute under prefix
    if not os.path.isabs(datadir):
        datadir = os.path.join(prefix, datadir)

    eggdrop_dir = os.path.join(datadir, 'eggdrop')

    print(f"Eggdrop installed to {prefix}")

    for subdir in ('pid', 'logs'):
        target = os.path.join(eggdrop_dir, subdir)
        if not os.path.exists(target):
            os.makedirs(target, exist_ok=True)
            print(f"Created directory: {target}")
        else:
            print(f"Directory already exists: {target}")


if __name__ == '__main__':
    main()
