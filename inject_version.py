#!/usr/bin/env python
import os
import subprocess

TID_FILE = "src/tiddlers/system/plugins/security_tools/twsm.tid"
VERSION_FILE = "VERSION"

def get_commit_count():
    return int(subprocess.check_output(["git", "rev-list",  "--count", "HEAD"]).decode('utf-8'))

def main():

    with open(VERSION_FILE, "r") as f:
        version = f.read().strip()
        # Some sanity
        mm = version.split(".")
        assert len(mm) == 2, "Expected version format MAJOR.MINOR"
        assert int(mm[0]) + int(mm[1]), "Expected version integers MAJOR.MINOR"

    ls = list()
    with open(TID_FILE, "r") as f:
        version_string = "version: {}.{}".format(version, get_commit_count())
        for l in f:
            if l.startswith("version:"):
                print("Injecting version: {}".format(version_string))
                ls.append(version_string + "\n")
            else:
                ls.append(l)

    with open(TID_FILE, "w") as f:
        f.write("".join(ls))
    print("Finished")

if __name__ == "__main__":
    main()