import os,sys
import json,time

tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER", 
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
         0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }
def print_():
    print "---------------------------------+--------------------------------+---------------------------------------------------------------"
def printtt_():
    print "\t\t\t\t +--------------------------------+---------------------------------------------------------------"

def getTags(tagParam):
    """
    Retrieve the tag names found within a tag
    """
    
    tagsFound = []
    for tag in tags.keys():
        if tags[tag] in tagParam:
            tagsFound.append(tags[tag])
    return tagsFound
def print_to_line(data):
    s =  data.replace("\r\n"," ")
    return s
def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """
    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
	bytes.append(chr(int(hexStr[i:i+2], 16)))
    return unicode(''.join( bytes ), errors='replace')
def print_to_line(data):
    s = ''.join(data.split("\n"))
    return s

start = time.time()

filename = sys.argv[1]#print len(sys.argv)
if not os.path.exists(filename):
    print "%s doesn't exist" % filename
    sys.exit(0)
opennet_dic = dict()
f = open(filename, 'r')
load = json.load( f )#print "%s\n" % load
#print file name
if load.has_key('apkName'):
	print "\n\napkName:%s\n" % load['apkName']
'''
if load.has_key('opennet'):# ip:host
			opennet = load['opennet']
			keys = opennet.keys()
			keys.sort()
			if len(keys) != 0:
				for key in keys:
					temp = opennet[key]
					try:
						opennet_dic[temp['desthost']] = temp['destport']
					except ValueError:
						pass
					except KeyError:
						pass
print len(opennet_dic)  #681
for k in opennet_dic.keys():
	print "%s: %s" % (k,opennet_dic[k])
	
if load.has_key('fdaccess'):
	fdaccess = load['fdaccess']
	keys = fdaccess.keys()
	keys.sort()
	print "\n\n"  + "\033[1;48m[File activities]\033[1;m\n"  + "-----------------\n"
	print '\033[1;48m[Read operations]\033[1;m\n'  + '-----------------'
	path = list()
	#print len(keys)
	
	for key in keys:
	    temp = fdaccess[key]
	    try:
		if temp['operation'] == 'read':
		    s=temp['path'].split('/')
		    print "[\033[1;36m%s\033[1;m]\t\t Path: %s" % (str(key), temp['path'])
		    print s[-1]
		    
	    except ValueError:
		pass
	    except KeyError:
		pass
	
	
	print '\033[1;48m[Write operations]\033[1;m\n'  + '------------------'
	for key in keys:                                                       
	    temp = fdaccess[key]
	    try:
		if temp['operation'] == 'write':
		   
		    s=temp['path'].split('/')
		    print "[\033[1;36m%s\033[1;m]\t\t Path: %s" % (str(key), temp['path'])
		    print s[-1]
		    
	    except ValueError:
		pass
	    except KeyError:
		pass
'''
if load.has_key('sendnet'):
	sendnet = load['sendnet']
	print "\n"  + "\033[1;48m[send message]\033[1;m\n" + "------------------"
	keys = sendnet.keys()
	keys.sort()
	for key in keys:
	    temp = sendnet[key]
	    try:
		print "[\033[1;36m%s\033[1;m]\t\t Destination: %s Port: %s" % ( str(key), temp['desthost'], temp['destport'])
		print "\t\t\t\t Data: %s" % (hexToStr(temp['data'])) + '\n'
	    except ValueError:
		pass
	    except KeyError:
		pass
if load.has_key('recvnet'):
	recvnet = load['recvnet']
	print "\n"  + "\033[1;48m[Incoming traffic]\033[1;m\n" + "------------------"
	keys = recvnet.keys()
	keys.sort()
	for key in keys:
	    temp = recvnet[key]
	    try:
		print "\033[1;36m%s\033[1;m]\t\t Source: %s Port: %s" % (str(key), temp['host'], temp['port'])
		print " Data: %s" % ( hexToStr(temp['data']))
		data = hexToStr(temp['data'])
		#data= ''.join(data.split("\n"))
		data = data.replace("\r\n"," ")
		print data
	    except ValueError:
		pass
	    except KeyError:
		pass
'''
tag_all = list()
if load.has_key('dataleaks'):
	dataleaks = load['dataleaks']
	keys = dataleaks.keys()
	keys.sort()
	num_network = num_sms = num_file = 0
	if len(keys) > 0:
		print "\n"  + "\033[1;48m[Information leakage]\033[1;m\n"  + "---------------------"
		for key in keys:
		    temp = dataleaks[key]
		    try:
			print "[\033[1;36m%s\033[1;m]\t\t Sink: %s" % ( str(key), temp['sink'])
			if temp['sink'] == 'Network':
			    print "\t\t\t\t Destination: %s" % ( temp['desthost'])
			    print "\t\t\t\t Port: %s" % (temp['destport'])
		    	    s = ', '.join(getTags((temp['tag'])))
			    print "\t\t\t\t Tag: %s" % ( s)
			    print len(s)
			    print "\t\t\t\t Data: %s" % (hexToStr(temp['data']))

			if temp['sink'] == 'File':
			    print "\t\t\t\t Path: %s" % (temp['path'])
			    print "\t\t\t\t Operation: %s" % ( temp['operation'])
			    print "\t\t\t\t Tag: %s" % (', '.join(getTags((temp['tag']))))
			    print "\t\t\t\t Data: %s" % ( hexToStr(temp['data']))

			if temp['sink'] == 'SMS':
			    print "\t\t\t\t Number: %s" % (temp['number'])
			    print "\t\t\t\t Tag: %s" % ( ', '.join(getTags((temp['tag']))))
			    print "\t\t\t\t Data: %s" % (temp['data'])
			for i in temp['tag']:
				tag_all.append(i)
		    except ValueError:
			pass
		    except KeyError:
			pass
		tagall = list(set(tag_all))
		for i in tagall:
			print i
		
		for key in keys:
		    temp = dataleaks[key]
		    try: 
			if temp['sink'] == 'Network':
			    num_network = num_network + 1
			elif temp['sink'] == 'File':
			    num_file = num_file + 1
			elif temp['sink'] == 'SMS':
			    num_sms = num_sms + 1
		    except ValueError:
			pass
		    except KeyError:
			pass
		print ("{0:^36} {1:64} {2:64} ".format("\033[1;48mInformation leakage:\033[1;m", "|[Source]", "|[Sink]"))
	        printtt_()
		if num_network > 0:
			for key in keys:
			    temp = dataleaks[key]
			    try: 
				if temp['sink'] == 'Network':
				   tag_str = ', '.join(getTags(temp['tag']))
				   if len("WebServer:"+temp['desthost']) > 38:
					sink = "WebServer:"+temp['desthost'][:29] +"..."
				   else:sink = "WebServer:"+temp['desthost']
				   if len("|"+tag_str) >= 64:
					source = "|"+tag_str[:60]+"..."
				   else:source = "|"+tag_str
				   print ("{0:24} {1:64} {2:10} {3:42}".format("", source,"|Network",sink))
			    except ValueError:
				pass
			    except KeyError:
				pass
		if num_file > 0:
			for key in keys:
			    temp = dataleaks[key]
			    try:
				if temp['sink'] == 'File':
				    tag_str = ', '.join(getTags(temp['tag']))
				    #print len("filePath:"+temp['path'])
				    if len("filePath:"+temp['path']) > 38:
					sink = "filePath:"+temp['path'][:30] +"..."
				    else:sink = "filePath:"+temp['path']
				    if len("|"+tag_str) >= 64:
					source = "|"+tag_str[:60]+"..."
				    else:source = "|"+tag_str
				    print ("{0:24} {1:64} {2:10} {3:42}".format("", source,"|File",sink))
			    except ValueError:
				pass
			    except KeyError:
				pass
		if num_sms > 0:
			for key in keys:
			    	temp = dataleaks[key]
			    	try:
				    if temp['sink'] == 'SMS':
				    	tag_str = ', '.join(getTags(temp['tag']))
					if len("phoneNumber:"+temp['number']) > 38:
					    sink = "phoneNumber:"+temp['number'][:27] +"..."
				        else:sink = "phoneNumber:"+temp['number']
				        if len("|"+tag_str) >= 64:
					    source = "|"+tag_str[:60]+"..."
				        else:source = "|"+tag_str
				        print ("{0:24} {1:64} {2:10} {3:42}".format("", source,"|SMS",sink))
				    	
				except ValueError:
				    pass
			    	except KeyError:
				    pass
			    #print "\t\t\t\t Tag: %s" % ( ', '.join(getTags(int(temp['tag'], 16))))
'''
end = time.time()
print "duration:%s s"%str(end-start)


