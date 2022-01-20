from __future__ import print_function
import frida
import sys
import os

def on_message(message, data):
    if (message["payload"]=="Output"):
        if (os.path.exists("test.data")):
            os.remove("test.data")
        with open("test.data","wb") as wf:
            wf.write(data)
    else:
        print("Message: "+str(message))
        #print("[%s] => %s" % (message, data))

def main(target_process):
    pid = frida.spawn([target_process])
    session = frida.attach(pid)
    script = session.create_script("""
    lang=Module.findExportByName("kernel32","GetSystemDefaultLCID");

    Interceptor.attach(lang, { 
                        onEnter: function (args) {
                            console.log('Found backdoor function');
                        },

                        // When function is finished
                        onLeave: function (retval) {
                            retval=0x804;
                            console.log('Press F8 to enable read backdoor, Password: oneplus');
                            return retval;
                        }
                    });
""")
    script.on('message', on_message)
    script.load()
    frida.resume(pid)
    print("[!] Ctrl+D on UNIX, Ctrl+C on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print ("Oppo MSMDownloadTool V4.0 Backdoor enabler (c) B.Kerler 2022\n") 
        print ("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)