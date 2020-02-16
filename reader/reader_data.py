#!/usr/bin/env python3

from google.protobuf import text_format
 
import sys
import os
import data_pb2 as pbutil

function = pbutil.DataList()

filename = sys.argv[1]
pb = open(filename, 'rb')
f = open(filename[:-3]+'.txt', 'w')
function.ParseFromString(pb.read())
f.write(text_format.MessageToString(function))
f.close()
pb.close()
