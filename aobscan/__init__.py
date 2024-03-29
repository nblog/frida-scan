#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os, sys, time, json, random, base64, codecs
from typing import List, Dict, Optional
from pydantic import BaseModel
from pydantic import BaseModel, ValidationError
from pydantic.functional_validators import AfterValidator
import frida

class frida_init:
    def __init__(self, process_object, scriptjs:str, **options):
        self.device = frida.get_device_manager().add_remote_device(options['remote']) \
            if options.get('remote') else \
            frida.get_local_device()

        self.session = self.device.attach(process_object)

        scriptcode = \
            codecs.open(scriptjs, encoding='utf-8-sig').read()
        self.script = self.session.create_script(scriptcode)

        self.script.on("message", lambda msg, data: ())
        self.script.load()

    def rpc(self, name):
        return getattr(self.script.exports_sync, name)


class aobscan_exception(Exception):
    ''' '''


''' data model '''

def eval_expr(expr:str, table:dict):
    return int( eval(expr, None, table) )

class ins_equal(BaseModel):
    cmd: str
    range: int = 16

class aob_data(BaseModel):
    mode: str
    pattern: str
    selected: Optional[int] = 1
    offset: Optional[str] = '0' # val_expr
    equal: Optional[ins_equal] = None

class pattern_data(BaseModel):
    name: str
    note: Optional[str] = ''
    value: Optional[str] = '0'  # val_expr
    aob: Optional[List[aob_data]] = None

class pattern_json(BaseModel):
    patterns: List[pattern_data]
    module: Optional[str] = ''



class program_aobscan:
    def __init__(self, process_object, aobscanjs:str, **options):
        self.app = frida_init(process_object, aobscanjs, **options)
        self.update_data:Dict[str, int] = {}

    def export(self, file_json="export.json"):
        json.dump(self.update_data, 
            open(file_json, 'w', encoding='utf-8-sig'))
        return

    def scan(self, file_json:str):
        caches = self.update_data.copy()

        cfgJson = pattern_json(**json.load( \
            codecs.open(file_json, encoding='utf-8-sig')))

        ''' rpc: change module '''
        if (cfgJson.module):
            self.__change_module(cfgJson.module)
    
        for pattern in cfgJson.patterns:
            ''' empty '''
            if (not pattern.name): continue

            ''' duplicate name '''
            if (pattern.name in caches):
                raise aobscan_exception("duplicate name: %s" % pattern.name)

            ''' default value '''
            caches[ pattern.name ] = \
                eval_expr(pattern.value, caches)

            ''' searches '''
            for aob in pattern.aob:
                aob.offset = str(eval_expr(aob.offset, caches))

                ''' rpc: aob-scan '''
                vJson = pattern.model_dump(include={'name', 'note'})
                rva = self.__aobscan(dict(vJson, **aob.model_dump()))
                if (not rva): continue

                ''' override '''
                caches[ pattern.name ] = rva
                if (rva): break

        self.update_data.update(caches)

        ''' version '''
        self.update_data.setdefault('#version', self.__program_version(cfgJson.module))


    def __change_module(self, module:str):
        return self.app.rpc("searchmodule")(module)

    def __aobscan(self, aob:dict):
        return self.app.rpc("aobscan")(aob)

    def __program_version(self, module=''):
        import win32api
        target = self.app.rpc("modulepath")(module)
        info = win32api.GetFileVersionInfo(target, "\\")
        ms, ls = info['FileVersionMS'], info['FileVersionLS']
        return '{}.{}.{}.{}'.format(
            win32api.HIWORD(ms), win32api.LOWORD(ms),
            win32api.HIWORD(ls), win32api.LOWORD(ls)
        )