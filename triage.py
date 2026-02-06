#!/usr/bin/python3
import os
import sys
import argparse

try:
    import lldb
except ImportError:
    with os.popen("lldb -P") as stream:
        output = stream.read()
    sys.path.append(output.rstrip())
    import lldb
import analyzer as analyzer_osx

class CrashTriageOSX():
    EXE = None
    LAUNCH_INFO = None

    def disassemble_instructions(self,insts):
        for i in insts:
            self.triage_debug(i)

    def triage_debug(self, content):
        with open('/tmp/triage_debug.txt', 'a') as file:
            file.write(content + "\n")
            print(content)

    def run_lldb(self):
        # Set the path to the executable to debug
        #self.EXE = "./a.out"

        # Create a new debugger instance
        debugger = lldb.SBDebugger.Create()

        # When we step or continue, don't return from the function until the process
        # stops. Otherwise we would have to handle the process events ourselves which, while doable is
        #a little tricky.  We do this by setting the async mode to false.
        debugger.SetAsync(True)

        # Create a target from a file and arch
        self.triage_debug("Creating a target for '%s'" % self.EXE)

        target = debugger.CreateTargetWithFileAndArch (self.EXE, lldb.LLDB_ARCH_DEFAULT)
        command_interpreter = debugger.GetCommandInterpreter()

        if target:
            # If the target is valid set a breakpoint at main
         #   main_bp = target.BreakpointCreateByName ("main", target.GetExecutable().GetFilename());

          #  self.triage_debug(main_bp)

            # Launch the process. Since we specified synchronous mode, we won't return
            # from this function until we hit the breakpoint at main
            #process = target.LaunchSimple (None, None, os.getcwd())

            error = lldb.SBError()
            process = target.Launch(self.LAUNCH_INFO, error)

            # Make sure the launch went ok
            if process:
                pid = process.GetProcessID()
                # Print some simple process info
                state = process.GetState ()
                #self.triage_debug(process)

                listener = debugger.GetListener()
                event = lldb.SBEvent()

                done = False
                while not done:
                    if listener.WaitForEvent(1, event):
                        if lldb.SBProcess.EventIsProcessEvent(event):
                            state = lldb.SBProcess.GetStateFromEvent(event)

                            if state == lldb.eStateInvalid:
                                # Not a state event
                                self.triage_debug('process event = ' + event)
                            else:
                                if state == lldb.eStateStopped:
                                    self.triage_debug("process stopped: " + str(pid) + "\n")
                                    # handle initial stop event after attach ( including attach_wait )

                                    # OK, now it's a 'real' stop.

                                    # skip ahead to the first faulting thread. Not perfect, but better
                                    # than nothing.
                                    # TODO: Handle cases where multiple threads have a StopReason
                                    # ( need to find one first )
                                    for thread in process:
                                        if thread.GetStopReason() != lldb.eStopReasonNone:
                                            process.SetSelectedThread(thread)
                                            break

                                    if not process.selected_thread.GetFrameAtIndex(0).IsValid():
                                        self.triage_debug("[ABORT] no valid frames in faulting thread")
                                        done = True
                                        continue

                                    # Adding some parser sugar...
                                    self.triage_debug("Stack trace:")
                                    self.run_commands(command_interpreter, ['bt 25'])


                                    self.triage_debug("Nearby code:")
                                    try:
                                        self.run_commands(command_interpreter, ['disass -p -c 10 -b'])
                                    except:
                                        self.triage_debug("<disassembly failed>")


                                    analyzer = analyzer_osx.Analyzer(target)

                                    self.triage_debug("ANALYSIS INDICATORS:")
                                    self.triage_debug("--------------------")
                                    self.triage_debug("StopDesc:           %s" % analyzer.getStopDescription())
                                    self.triage_debug("AvNearNull:         %s" % analyzer.isAvNearNull())
                                    self.triage_debug("AvNearSP:           %s" % analyzer.isAvNearSP())
                                    self.triage_debug("BadBeef:            %s" % analyzer.isAvBadBeef())
                                   # self.triage_debug("Access Type:        %s" % analyzer.getAccessType(analyzer.getCurrentInstruction()))
                                    #regs = analyzer.getInsnRegisters(analyzer.getCurrentInstruction())
                                    #self.triage_debug("Registers:          %s" % ' '.join(map(lambda r: "{}={}".format(r, regs[r]), regs.keys())))
                                    #self.triage_debug("BlockMov:           %s" % analyzer.isBlockMove())
                                    self.triage_debug("Weird PC:           %s" % analyzer.isPcWeird())
                                   # self.triage_debug("Weird SP:           %s" % analyzer.isSpWeird())
                                    self.triage_debug("Suspicious Funcs:   %s" % " ".join(analyzer.getSuspiciousStackFuncs()))
                                    self.triage_debug("Illegal Insn:       %s" % analyzer.isIllegalInstruction())
                                    self.triage_debug("Huge Stack:         %s" % analyzer.isStackHuge())


                                    done = True



                                elif state == lldb.eStateExited:
                                    exit_desc = process.GetExitDescription()
                                    if exit_desc:
                                        self.triage_debug("process exited with status " + str(pid) + " " + str(process.GetExitStatus()) + " " + exit_desc)
                                    else:
                                        self.triage_debug("process exited with status " + str(pid) + " " + str(process.GetExitStatus()))
                                    done = True
                                elif state == lldb.eStateCrashed:
                                    # TODO no idea when this happens without first hitting a stop event
                                    self.triage_debug("process crashed" + str(pid))
                                    done = True
                                elif state == lldb.eStateDetached:
                                    self.triage_debug("process detached " + str(pid))
                                    done = True
                                elif state == lldb.eStateRunning:
                                    self.triage_debug("process resumed " + str(pid))
                                elif state == lldb.eStateUnloaded:
                                    self.triage_debug("process unloaded, this shouldn't happen " + str(pid))
                                    done = True
                                elif state == lldb.eStateConnected:
                                    self.triage_debug("process connected")
                                elif state == lldb.eStateAttaching:
                                    self.triage_debug("process attaching")
                                elif state == lldb.eStateLaunching:
                                    self.triage_debug("process launching")
                        else:
                            self.triage_debug('event = %s' % (event))



            process.Kill()
        lldb.SBDebugger.Terminate()

    def run_commands(self, command_interpreter, commands):
        return_obj = lldb.SBCommandReturnObject()
        for command in commands:
            command_interpreter.HandleCommand(command, return_obj)
            if return_obj.Succeeded():
                self.triage_debug(return_obj.GetOutput())


    def main(self):
        if(len(sys.argv) < 2):
            print("./triage binary args")
            exit(1)

        self.triage_debug("----------------------------------------------------------------------------------------------")
        self.triage_debug("Running with following args: "+str(sys.argv))
        self.EXE = sys.argv[1]
        sys.argv.pop(0)
        sys.argv.pop(0)
        self.LAUNCH_INFO = lldb.SBLaunchInfo(sys.argv)
        env_vars = os.environ
        env_vars_list = [f'{key}={value}' for key, value in env_vars.items()]
        self.LAUNCH_INFO.SetEnvironmentEntries(env_vars_list, True)
        self.run_lldb()


if __name__ == "__main__":
    CrashTriageOSX().main()
