#!c:\python\python.exe

# $Id: tracer_single_step.py 194 2007-04-05 15:31:53Z cameron $

import sys

from pydbg import *
from pydbg.defines import *

USAGE = "USAGE: tracer_single_step.py <PID>"
error = lambda msg: sys.stderr.write("ERROR> " + msg + "\n") or sys.exit(1)
begin = 0
end   = 0

########################################################################################################################
def handler_breakpoint (dbg):
    global begin, end

    if not begin or not end:
        print "initial breakpoint hit at %08x: %s" % (dbg.exception_address, dbg.disasm(dbg.exception_address))
        print "putting all threads into single step mode"

        for module in dbg.iterate_modules():
            if module.szModule.lower().endswith(".exe"):
                begin = module.modBaseAddr
                end   = module.modBaseAddr + module.modBaseSize
                print "%s %08x -> %08x" % (module.szModule, begin, end)

        for tid in dbg.enumerate_threads():
            print "    % 4d -> setting single step" % tid
            handle = dbg.open_thread(tid)
            dbg.single_step(True, handle)
            dbg.close_handle(handle)

    elif begin <= dbg.exception_address <= end:
        print "%08x: %s" % (dbg.exception_address, dbg.disasm(dbg.exception_address))

    dbg.single_step(True)
    return DBG_CONTINUE


########################################################################################################################
def handler_single_step (dbg):
    global begin, end

    disasm    = dbg.disasm(dbg.exception_address)
    ret_addr  = dbg.get_arg(0)
    in_module = False

    if begin <= dbg.exception_address <= end:
        print "%08x: %s" % (dbg.exception_address, disasm)
        in_module = True

    # if the current instructon is 'sysenter', set a breakpoint at the return address to bypass it.
    if disasm == "sysenter":
        dbg.bp_set(ret_addr)

    # if the current instruction is outside the main module and the return instruction is not, set a breakpoint on it
    # and continue without single stepping.
    elif not in_module and begin <= ret_addr <= end and ret_addr != 0:
        dbg.bp_set(ret_addr)

    # otherwise, re-raise the single step flag and continue on.
    else:
        dbg.single_step(True)

    return DBG_CONTINUE


########################################################################################################################
def handler_new_thread (dbg):
    dbg.single_step(True)
    return DBG_CONTINUE


if len(sys.argv) != 2:
    error(USAGE)

try:
    pid = int(sys.argv[1])
except:
    error(USAGE)

dbg = pydbg()

dbg.set_callback(EXCEPTION_BREAKPOINT,      handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP,     handler_single_step)
dbg.set_callback(CREATE_THREAD_DEBUG_EVENT, handler_new_thread)

dbg.attach(pid)
dbg.run()
