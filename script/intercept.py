#! /usr/bin/python

import frida
import sys
import ctypes
import json

def main():
    mod = ctypes.cdll.LoadLibrary("libhook.dylib")
    ret = mod.init() | mod.enable()
    if ret != 0:
        print("initializing libhook.dylib failed. Quit!")
        return
    mod.collect.restype = ctypes.c_char_p

    session = frida.attach("bluetoothd")
    pid = frida.get_local_device().get_process("bluetoothd").pid
    # print("{\"pid\": %d}" % pid)
    
    script = session.create_script("""
      // Utility
      function scanPtr(nativePtr, length, ptrs) {
        // console.log(nativePtr, length, JSON.stringify(ptrs));
        var i = 0;
        var data = [];
        var fields = [];
        for ( ; i + 8 <= length; i += 8) {
          try {
            var addr = nativePtr.add(i).readU64();
            var j = 0;
            for ( ; j < ptrs.length; j++) {
              var tgt = uint64(ptrs[j]["addr"]);
              if (addr.compare(tgt) == 0) {
                var field = scanPtr(nativePtr.add(i).readPointer(), ptrs[j]["size"], ptrs);
                if (data.length != 0) {
                  fields.push({"type": "buffer", "data": data});
                  data = [];
                }
                fields.push(field);
                break;
              }
            }
            if (j != ptrs.length) {
              continue;
            }
          } catch (err) {
            // nothing to do
            console.log(err);
          }

          for (var j = i; j < i + 8; j++) {
            try {
              data.push(nativePtr.add(j).readU8());
            } catch(err) {
              console.log(err);
              break;
            }
          }
        }

        // Left over data
        for ( ; i < length; i++) {
          try {
            data.push(nativePtr.add(i).readU8());
          } catch(err) {
            break;
          }
        }
        if (data.length != 0) {
          fields.push({"type": "buffer", "data": data})
        }

        if (fields.length == 1) {
          fields[0]["ptr"] = nativePtr;
          return fields[0];
        }
        return {"type": "struct", "fields": fields, "ptr": nativePtr};
      }

      Interceptor.attach(Module.getExportByName("IOKit", "IOConnectCallMethod"), {
        onEnter: function (args) {
          var dict = {
            "name": "IOConnectCallMethod",
            "port": args[0].toInt32(),
            "selector": args[1].toInt32(),
            "inputStructSize": args[5].toInt32(),
            "inputStructPtr": args[4],
            "outputStructPtr": args[8],
          };
          if (args[9].isNull()) {
            dict["outputStructSize"] = 0;
          } else {
            dict["outputStructSize"] = args[9].readInt();
          }
          this.IOData = dict;
        },
        onLeave: function (retVal) {
          if (this.IOData) {
            try {
            this.IOData["ret"] = retVal.toInt32();
            var infos = null;
            send(0);
            var op = recv('input', function(value) {
              if (value.hasOwnProperty("payload")) {
                infos = value["payload"];
              }
            });
            op.wait();

            if (infos) {
              // read outputStruct
              var output = [];
              var outputPtr = this.IOData["outputStructPtr"];
              if (!outputPtr.isNull()) {
                for (var i = 0; i < this.IOData["outputStructSize"]; i++) {
                  output.push(outputPtr.add(i).readU8());
                }
              }
              this.IOData["outputStruct"] = output;

              // read inputStruct
              var input = scanPtr(this.IOData["inputStructPtr"], this.IOData["inputStructSize"], infos["ptrs"])
              this.IOData["inputStruct"] = input;

              this.IOData["id"] = infos["id"]
            }

            console.log(JSON.stringify(this.IOData));
            } catch(err) {
              console.log(err);
            }
          }
          this.IOData = null;
        }
      });
    """)

    def on_message(message, data):
        ret = mod.collect(pid)
        mod.enable()
        # print(ret)
        try:
            item = json.loads(ret)
            new_ptrs = []
            ptrs = []
            for i in range(len(item["ptrs"])):
            	addr = item["ptrs"][i]&0xffffffffffff
            	size = ((item["ptrs"][i]&0xfffffffffffffff)>>48)&0xfff
            	if addr not in ptrs:
            		ptrs.append(addr)
            		new_ptrs.append({"addr": addr, "size": size})
            item["ptrs"] = new_ptrs
            script.post({'type': 'input', 'payload': item})
        except Exception as e:
            print(e)
            script.post({'type': 'input'})


    script.on('message', on_message)
    script.load()
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        mod.disconnect()
        session.detach()

if __name__ == "__main__":
	main()