#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
import json
from argparse import ArgumentParser

def start(func):
    argp = ArgumentParser()
    argp.add_argument("in_file",help="input json file")
    argp.add_argument("out_file",help="output json file")
    
    args = argp.parse_args()
    
    with open(args.in_file) as fp:
        in_param = json.load(fp)
    
    rval = func(in_param)
    
    with open(args.out_file,"w") as wfp:
        json.dump(rval, wfp)
        

def put_log(log_level, msg:str, args):
    
    log_msg = msg % args
    
    for l in log_msg.splitlines():
        print(f"{log_level}:{l}",flush=True)

def log_debug(msg, *args):
    put_log("DEBUG",msg, args)

def log_info(msg, *args):
    put_log("INFO",msg, args)

def log_warning(msg, *args):
    put_log("WARNING",msg, args)

def log_error(msg, *args):
    put_log("ERROR",msg, args)
    
def set_progress(val:int):
    val = int(val)
    print(f"[#] {val:d}",flush=True)

