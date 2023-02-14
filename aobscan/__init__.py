#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os, sys, time, json, random, base64, codecs


''' frida '''
import frida

class frida_init:
    def __init__(self, process_object, scriptjs:str, remote=False):
        self.device = frida.get_remote_device() if (remote) else \
            frida.get_local_device()

        self.session = self.device.attach(process_object)

        scriptcode = \
            codecs.open(scriptjs, "r", encoding="utf-8-sig").read()
        self.script = self.session.create_script(scriptcode)

        self.script.on("message", lambda msg, data: ())
        self.script.load()

    def rpc(self, name):
        return getattr(self.script.exports_sync, name)



class aobscan_exception(Exception):
    ''' '''


class equal_data:
    cmd: str    # required
    range: int  # optional

    def __init__(self, vJson:dict):
        (self.cmd, self.range) = (None, 16)
        for n in vJson: self.__setattr__(n, vJson[n])

class aob_data:
    pattern: str # required
    mode: str    # required
    offset: str  # optional
    equal: equal_data # optional

    def __init__(self, vJson:dict):
        (self.pattern, self.mode, self.offset, self.equal) = \
            (None, None, "0", None)
        for n in vJson: self.__setattr__(n, vJson[n])

        if (self.equal): self.equal = equal_data(self.equal)

class pattern_data:
    name: str   # required
    aob: list[aob_data] # optional
    note: str   # optional
    value: str  # optional

    def __init__(self, vJson:dict):
        (self.name, self.aob, self.note, self.value) = \
            (None, [], "dummy", "0")
        for n in vJson: self.__setattr__(n, vJson[n])

        if (self.aob): self.aob = list(map(aob_data, self.aob))


class program_aobscan:

    def __init__(self, process_object, aobscanjs="aobscan.js"):
        self.update_data = dict[str, int]()
        self.app = frida_init(process_object, aobscanjs)


    def export(self, file_json="export.json"):
        json.dump(self.update_data, 
            codecs.open(file_json, "w", encoding="utf-8-sig"))
        return

    def scan(self, file_json:str):
        caches = self.update_data.copy()

        vJson = json.load(
            codecs.open(file_json, "r", encoding="utf-8-sig")
        )

        if (not "patterns" in vJson): return

        ''' rpc: change module '''
        if ("module" in vJson):
            self.__change_module(vJson["module"])

        for pattern in map(pattern_data, vJson["patterns"]):
            ''' empty '''
            if (not pattern.name): continue

            ''' duplicate name '''
            if (pattern.name in caches):
                raise aobscan_exception("duplicate name: %s" % pattern.name)

            ''' default value '''
            caches[ pattern.name ] = \
                self.__eval_expr(pattern.value, caches)

            ''' searches '''
            for aob in pattern.aob:
                ''' required '''
                if (not aob.pattern or not aob.mode):
                    raise aobscan_exception("invalid aob: %s" % pattern.name)

                ''' eval '''
                offset = \
                    self.__eval_expr(aob.offset, caches)

                ''' rpc: aob-scan '''
                rva = self.__aobscan({
                    "note": pattern.note,
                    "offset": offset,
                    "mode": aob.mode,
                    "pattern": aob.pattern,
                    "equal": aob.equal and aob.equal.__dict__,
                })

                ''' override '''
                caches[ pattern.name ] = rva

                if (rva): break

        self.update_data.update(caches)

    def __eval_expr(self, expr:str, table:dict):
        return int( eval(expr, None, table) )

    def __change_module(self, module:str):
        return self.app.rpc("searchmodule")(module)

    def __aobscan(self, aob:dict):
        return self.app.rpc("aobscan")(aob)