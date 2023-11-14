#!/usr/bin/env python3
# -*- coding: utf-8 -*-



if __name__ == "__main__":

    from aobscan import program_aobscan


    app = "wechat.exe" # or pid

    updater = program_aobscan(app, "aobscan\\aobscan2.js")

    updater.scan("update_example.json"); updater.export("export.json")

    print("done")