from __future__ import print_function
import frida
import sys
import os
i=0
def on_message(message, data):
    global i
    if "payload" in message:
        if (message["payload"]=="Output"):
            if os.path.exists("decrypted.data"+str(i)):
                os.remove("decrypted.data"+str(i))
            with open("decrypted.data"+str(i),"wb") as wf:
                wf.write(data)
                print("Decrypted data was written to 'decrypted.data"+str(i)+"'.")
            i+=1
    else:
        print("[%s] => %s" % (message, data))

def main(target_process):
    pid = frida.spawn([target_process])
    session = frida.attach(pid)
    script = session.create_script("""
    var seekoffset=0;
    var seeklength=0;
    var processname="";
    
    var op = recv('param', function(value) {
                var v = value.payload.split(",");
                processname = v[0];
                run();
                });

    function run()
    {
        var proc=Module.findBaseAddress(processname);
        var base=Process.findRangeByAddress(proc);
        var fileptr=Module.findExportByName("kernel32","SetFilePointer");
        var readfileptr=Module.findExportByName("kernel32","ReadFile");
        
        /*Memory.scan(base.base, 0x100000, "55????5D????FFFFFFE9",
        { 
            onMatch: function(address,size) 
            {  
                console.log("Found MAlloc: "+ptr(address).toString(16));
                
                Interceptor.attach(ptr(address), { 
                            // When function is called, print out its parameters
                            
                            onEnter: function (args) {
                                console.log("Entered at :"+address.toString(16))
                                this.length=args[0].toInt32();
                                if (args[0]<0x16000)
                                {
                                    var subsize=args[0]
                                    Interceptor.attach(readfileptr, { 
                                        onEnter: function (args) {
                                            console.log('');
                                            console.log('[+] ReadFileLength: ' + args[2]);
                                            
                                            if (args[2].toString(16)==subsize.toString(16))
                                            {
                                                console.log('[+] Subsize: ' + subsize);
                                                args[2]=ptr(seeklength);
                                                console.log('[+] New ReadFileLength: ' + args[2]);
                                            }
                                            
                                        }
                                    });
                                    args[0]=ptr(seeklength);
                                    console.log('[+] New DLength: ' + args[0]);
                                }
                            },

                            onLeave: function (retval) {
                            }
                        });
            }, 
            
            onComplete: function() 
            { 
            } 
        });*/
        
        Memory.scan(base.base, 0x100000, "D1B5E39E",
        { 
            onMatch: function(address,size) 
            {  
                var z=0;
                for (z=address-50;z<address;z++) 
                { 
                    var h=Memory.readU8(ptr(z));
                    if (h==0x55)
                    {
                        console.log("Detected AES: "+ptr(z).toString(16));
                        Interceptor.attach(ptr(z), { // Intercept calls to our SetAesDecrypt function
                            // When function is called, print out its parameters
                            onEnter: function (args) {
                                console.log('');
                                console.log('[+] AES-Length: ' + args[0]);
                                console.log('[+] AES-EDX: ' + Memory.readU32(this.context.edx).toString(16)); // Plaintext
                                this.length=args[0].toInt32();
                                this.xx=this.context.edx;
                            },

                            // When function is finished
                            onLeave: function (retval) {
                                dumpAddr('Data', this.xx, 16); // Print out data array, which will contain de/encrypted data as output
                                var dt=Memory.readByteArray(this.xx,this.length);
                                send('Output',dt);
                                console.log("Writing data.");
                            }
                        });
                        break;
                    }
                }
            }, 
            
            onComplete: function() 
            { 
            } 
        });

        /*Interceptor.attach(fileptr, { 
                            onEnter: function (args) {
                                console.log('');
                                if (args[1]>0x0 && args[1]<0xFFFF0000)
                                {
                                    console.log('[+] Seek: ' + args[1]);
                                    args[1]=ptr(seekoffset);
                                }
                                
                            },

                            // When function is finished
                            onLeave: function (retval) {
                                
                            }
                        });*/
    }
    
                    
    function dumpAddr(info, addr, size) {
        if (addr.isNull())
            return;

        console.log('Data dump ' + info + ' :');
        var buf = Memory.readByteArray(addr, size);

        // If you want color magic, set ansi to true
        console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
    }
""")
    script.on('message', on_message)
    script.load()
    script.post({'type': 'param', 'payload': str(target_process)})
    frida.resume(pid)
    print("[!] Ctrl+C on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print ("Oppo MSMDownloadTool V4.01 Firmware decrypter (c) B.Kerler 2017-2022\n") 
        print ("Usage: %s <process name:MSMDownloadTool.exe>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)
