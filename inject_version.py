#!/usr/bin/env python
import os
import subprocess
import json

JSON_FILE = "plugins/security_tools/twsm/plugin.info"
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

    with open(JSON_FILE, "r") as f:
        j = json.load(fp=f)

    # Set the version
    j["version"] = "{}.{}".format(version, get_commit_count())

    # Re-write the file
    with open(JSON_FILE, "w") as f:
        json.dump(j, fp=f, indent=4)

    print("Finished")

if __name__ == "__main__":
    main()