#!/usr/bin/env python3

from google.protobuf import text_format
 
import sys
import os
import ghidump_pb2

print("   ________    _ ____                      ")
print("  / ____/ /_  (_) __ \__  ______ ___  ____ ")
print(" / / __/ __ \/ / / / / / / / __ `__ \/ __ \\")
print("/ /_/ / / / / / /_/ / /_/ / / / / / / /_/ /")
print("\____/_/ /_/_/_____/\__,_/_/ /_/ /_/ .___/ ")
print("                                  /_/      ")

if len(sys.argv) == 1:
  print ("Usage:", sys.argv[0], "programName.pb")
  sys.exit(-1)

else:
  ghidump = ghidump_pb2.GhiDumpMessage()
  
  for arg in sys.argv[1:]:
    if(os.path.exists(arg) == False):
        print(arg+" not found...")
        continue;
    
    pb = open(arg, 'rb')
    f = open(arg[:-3]+'.txt', 'w')
    print("Parsing "+arg+"...");
    ghidump.ParseFromString(pb.read())
    print("Writing "+arg[:-3]+".txt...");
    f.write(text_format.MessageToString(ghidump))
    f.close()
    pb.close()

print("Follow the white rabbit.")
