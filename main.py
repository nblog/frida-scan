#!/usr/bin/env python3
# -*- coding: utf-8 -*-



if __name__ == "__main__":

    from aobscan import program_aobscan

    import os, sys
    updater = program_aobscan(
        sys.argv[1], 
        os.path.join(os.path.dirname(sys.argv[0]), "aobscan" ,"aobscan2.js"))

    updater.scan(sys.argv[2]); updater.export(sys.argv[3])

    print("done")