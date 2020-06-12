
import frida
import sys

def main():
    session = frida.attach("bluetoothd")
    pid = frida.get_local_device().get_process("bluetoothd").pid
    print("{\"pid\": %d}" % pid)
    
    script = session.create_script("""
      // Utility
      var maxLenElements = [4, 8, 16, 32, 64, 128, 256, 512];
      //  1, 2, 4, 8, 16, 32, 32, 32
      var proportion = [1, 3, 7, 15, 31, 63, 95, 127];
      function genMaxLength() {
          var r = Math.floor(Math.random() * 127); 
          for (var i = 7; i > 0; i--) {
              if (r >= proportion[i-1]) {
                  return maxLenElements[i];
              }
          }
          return 4;
      }

      function scanPtr(nativePtr, maxLength, alignment, maxDepth, pool) {
          if (maxDepth == 0) {
              return {"type": "buffer", "data": []};
          }

          // var addr = nativePtr.toInt32();
          // if (addr % alignment != 0) {
          //     nativePtr = nativePtr.add(alignment - addr%alignment);
          // }
          var data = []
          var fields = []
          var i = 0;
          for ( ; i + 8 <= maxLength; i += alignment) {
              // console.log("read from ", i);
              try {
                  var aptr = nativePtr.add(i).readPointer(); // Can read a pointer?
                  aptr.readU8(); // The pointer is accessable?
                  // Find a plausible pointer
                  var field = scanPtr(aptr, 512, alignment, maxDepth-1, pool);
                  if (field != null) {
                      if (data.length != 0) {
                          fields.push({"type": "buffer", "data": data});
                          data = [];
                      }
                      // Try to minimize the size
                      var newMaxLength = genMaxLength();
                      if (field["type"] == "buffer" && field["data"].length > newMaxLength) {
                          // console.log(field["data"].length, newMaxLength);
                          field["data"] = field["data"].slice(0, newMaxLength);
                          var newPtr = Memory.alloc(newMaxLength);
                          Memory.copy(newPtr, aptr, newMaxLength);
                          nativePtr.add(i).writePointer(newPtr);
                          pool.push(newPtr);
                      }

                      // Auxiliary info
                      var range = Process.findRangeByAddress(aptr);
                      if (range) {
                          field["protection"] = range.protection;
                      }
                      field["ptr"] = aptr; 
                      fields.push(field);
                      continue;
                  }
              } catch(err) {
                  // nothing to do
                  // console.log(err);
              }
              for (var j = i; j < i + alignment; j++) {
                  try {
                      data.push(nativePtr.add(j).readU8());
                  } catch(err) {
                      break;
                  }
              }
          }
          // Left over data
          for ( ; i < maxLength; i++) {
              try {
                  data.push(nativePtr.add(i).readU8());
              } catch(err) {
                  break;
              }
          }
          if (data.length != 0) {
              fields.push({"type": "buffer", "data": data});
          }
          if (fields.length == 1) {
              return fields[0];
          }
          return {"type": "struct", "fields": fields, "ptr": nativePtr};
      }

      // Hook
      Interceptor.attach(Module.getExportByName("IOKit", "IOConnectCallMethod"), {
        onEnter: function (args) {
          var dict = {
            "name": "IOConnectCallMethod",
            "port": args[0].toInt32(),
            "selector": args[1].toInt32(),
            "inputStructSize": args[5].toInt32(),
          }
          // input data
          var pool = [];
          var data = scanPtr(args[4], dict["inputStructSize"], 8, 2, pool);
          dict["inputStruct"] = data;
          // output data
          if (args[9].isNull()) {
              dict["outputStructSize"] = 0;
          } else {
              dict["outputStructSize"] = args[9].readInt();
          }
          this.Pool = pool;
          this.OutputPtr = args[8];
          this.IOData = dict;
        },
      onLeave: function (retVal) {
          if (this.IOData) {
              this.IOData["ret"] = retVal;
              var data = [];
              if (!this.OutputPtr.isNull()) {
                  for (var i = 0; i < this.IOData["outputStructSize"]; i++) {
                      data.push(this.OutputPtr.add(i).readU8());
                  }
              }
              this.IOData["outputStruct"] = data;
              this.IOData["time"] = Date.now();
              console.log(JSON.stringify(this.IOData));
          }
          this.IOData = null;
          this.Pool = [];
      }
    });
    """)

    script.load()
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()

if __name__ == "__main__":
    main()

