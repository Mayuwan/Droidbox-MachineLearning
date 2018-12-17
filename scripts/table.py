# -*- coding: utf-8 -*- 
#read .json file and print to teiminal as table format
##############################################################################################
# -*- coding: utf-8 -*-  
import numpy as np  
import scipy as sp  
from sklearn import tree  
from sklearn.metrics import precision_recall_curve  
from sklearn.metrics import classification_report  
from sklearn.cross_validation import train_test_split  
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.externals import joblib
import os 
import os,sys
import json

sum_fileRead = 0
sum_fileWrite = 0
sum_recvnet = 0
sum_opennet = 0
sum_sendnet = 0
sum_cryptousage = 0
sum_dexclass = 0
sum_recvsaction = 0
sum_servicestart = 0
sum_enfperm = 0
sum_phonecalls = 0
sum_dataleaks = 0
sum_sendsms = 0
vector = []
vector_fileRead = vector_fileWrite = vector_opennet = vector_recvnet = vector_sendnet = vector_cryptousage = vector_dexclass = vector_recvsaction = vector_servicestart = vector_enfperm = vector_dataleaks= vector_sendsms = vector_phonecalls = 0


tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER", 
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
         0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }
def statistics(algo):
    algo.sort()
    dic = {}
    i = 0
    while i<len(algo):
	dic[algo[i]] = algo.count(algo[i])
	i = i + dic[algo[i]]
    return dic
def print_to_line(data):
    s =  data.replace("\r\n"," ")
    return s

def getTags(tagParam):
    """
    Retrieve the tag names found within a tag
    """
    
    tagsFound = []
    for tag in tags.keys():
        if tags[tag] in tagParam:
            tagsFound.append(tags[tag])
    return tagsFound
def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """
    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    #print hexStr
    for i in range(0, len(hexStr), 2):
	bytes.append(chr(int(hexStr[i:i+2], 16)))
    #print bytes
    #print ''.join( bytes )
    #return unicode(''.join( bytes ), errors='replace')
    return ''.join( bytes )#type:str
    #return bytes
def print_():
    print "-------------------------+--------------------------------+-------------------------------------------------------------------------------------"
def printtt_():
    print "\t\t\t +--------------------------------+-------------------------------------------------------------------------------"

path_json = sys.argv[2]
os.chdir(path_json)
filename = sys.argv[1]#print len(sys.argv)
if not os.path.exists(filename):
    print "%s doesn't exist" % filename
    sys.exit(0)

f = open(filename, 'r')
load = json.load( f )#print "%s\n" % load
#print file name
if load.has_key('apkName'):
	print "\n\napkName:%s\n" % load['apkName']

#record the sum of different behaviors
path_txt = sys.argv[3]
os.chdir(path_txt)
apk_name = os.path.splitext(filename)[0]
fw = open(apk_name+'.txt', 'w')
# Print file activity
print_()

if load.has_key('fdaccess'):
	fdaccess = load['fdaccess']
	keys = fdaccess.keys()
	keys.sort()
	if len(keys) != 0:
		for key in keys:
		    temp = fdaccess[key]
		    try:
			if temp['operation'] == 'read':
			    sum_fileRead = sum_fileRead + 1
			else:
			    sum_fileWrite = sum_fileWrite + 1
		    except ValueError:
			pass
		    except KeyError:
			pass
		# print file read
		if sum_fileRead > 0:
			print ("{0:^36} {1:32} {2:60}".format("\033[1;48mFile Read:\033[1;m", "|[PATH]", "|[Data]")) 
			printtt_()
			for key in keys:
			    temp = fdaccess[key]
			    try:
				if temp['operation'] == 'read':
				    data = hexToStr(temp['data'])
				    s = ''.join(data.split('\n'))
				    if len("|"+temp['path']) > 32:path = "|"+temp['path'][:28]+"..."
				    else:path = "|"+temp['path']
				    #print len("|" + s)
			   	    if len("|" + s) > 84: info = "|"+s[:65]+'...'
				    else: info = "|" + s
				    print ("{0:24} {1:32} {2:70}".format("", path, info))
			    except ValueError:
				pass
			    except KeyError:
				pass
			print_()
			vector_fileRead = 1
		# print file write
		if sum_fileWrite > 0:
			print ("{0:^36} {1:32} {2:60}".format("\033[1;48mFile Write:\033[1;m", "|[PATH]", "|[Data]")) 
			printtt_()
			for key in keys:
			    temp = fdaccess[key]
			    try:
				if temp['operation'] == 'write':
				    data = hexToStr(temp['data'])
				    s = ''.join(data.split('\n'))
 				    if len("|"+temp['path']) > 32:path = "|"+temp['path'][:28]+"..."
				    else:path = "|"+temp['path']
				    #print len("|" + s)
			   	    if len("|" + s) > 84: info = "|"+s[:65]+'...'
				    else: info = "|" + s
				    print ("{0:24} {1:32} {2:70}".format("", path, info))
			    except ValueError:
				pass
			    except KeyError:
				pasS
			print_()
			vector_fileWrite = 1	
	fw.write("sum_fileRead: %s\n" % str(sum_fileRead))
	fw.write("sum_fileWrite: %s\n" % str(sum_fileWrite))

#print Opened connections
if load.has_key('opennet'):
	opennet = load['opennet']
	keys = opennet.keys()
	keys.sort()
	if len(keys) != 0:
		print ("{0:^36} {1:32} {2:60}".format("\033[1;48mOpened connections:\033[1;m", "|[Destination]", "|[Port]")) 
		printtt_()
		for key in keys:
		    temp = opennet[key]
		    try:
			if len("|"+temp['desthost']) > 32:destination = "|"+temp['desthost'][:28]+"..."
			else:destination =  "|"+temp['desthost']
			print ("{0:24} {1:32} {2:60}".format("", destination, "|"+temp['destport']))
		    except ValueError:
			pass
		    except KeyError:
			pass
		print_()
		vector_opennet = 1
	fw.write("sum_opennet: %s\n" % str(len(keys)))

#print Incoming traffic
if load.has_key('recvnet'):
	recvnet = load['recvnet']
	keys = recvnet.keys()
	keys.sort()
	if len(keys) != 0:
		print ("{0:^36} {1:32} {2:10} {3:50}".format("\033[1;48mIncoming traffic:\033[1;m", "|[Source]", "|[Port]", "|[Data]")) 
		printtt_()
		for key in keys:
		    temp = recvnet[key]
		    try:
			data = hexToStr(temp['data'])
			if len("|"+temp['host']) > 32:source = "|"+temp['host'][:28]+"..."
			else: source = "|"+temp['host']
			print ("{0:^24} {1:32} {2:10} {3:42}".format("", source,"|"+temp['port'], "|"+print_to_line(data)[:35]+'...'))
		    except ValueError:
			pass
		    except KeyError:
			pass
		print_()
		vector_recvnet = 1
	fw.write("sum_recvnet: %s\n" % str(len(keys)))

#print Outgoing traffic
if load.has_key('sendnet'):
	sendnet = load['sendnet']
	keys = sendnet.keys()
	keys.sort()
	if len(keys) != 0:
		print ("{0:^36} {1:32} {2:10} {3:50}".format("\033[1;48mOutgoing traffic:\033[1;m", "|[Destination]", "|[Port]", "|[Data]")) 
		printtt_()
		for key in keys:
		    temp = sendnet[key]
		    try:
			data = hexToStr(temp['data'])
			#s =  data.replace("\r"," ")
			if len(temp['desthost']) >= 32:destination = "|"+temp['desthost'][:28]+"..."
			else:destination = "|"+temp['desthost'] 
			print ("{0:^24} {1:32} {2:10} {3:50}".format("", "|"+temp['desthost'],"|"+temp['destport'], "|"+print_to_line(data)[:50]+'...'))
		    except ValueError:
			pass
		    except KeyError:
			pass
		print_()
		vector_sendnet = 1
	fw.write("sum_sendnet: %s\n" % str(len(keys)))

# Print crypto API usage
if load.has_key('cryptousage'):
	cryptousage = load['cryptousage']
	keys = cryptousage.keys()
	keys.sort()
	num_keyalgo = 0
	num_other = 0
	if len(keys) > 0:
			print ("{0:^36} {1:32} {2:32} {3:10}".format("\033[1;48mCrypto API activities:\033[1;m","|[Operation]" ,"|[Algorithm]","|[Number]")) 
			printtt_()
			algo_keyalgo = list()
			algo = list()
			for key in keys:                                                               
			    temp = cryptousage[key]
			    try:
				if temp['operation'] == 'keyalgo':
				    algo_keyalgo.append(temp['algorithm'])
				else:
				    algo.append(temp['algorithm'])
				    operation = temp['operation']
			    except ValueError:
				pass
			    except KeyError:
				pass
			dic_keyalgo = statistics(algo_keyalgo)
			algo_keyalgo_keys = dic_keyalgo.keys()
			for k in algo_keyalgo_keys:
			    print ("{0:24} {1:32} {2:32} {3:5}".format("","|keyalgo","|"+k,"|"+str(dic_keyalgo[k])))
			dic = statistics(algo)
			algo_keys = dic.keys()
			for k in algo_keys:
			    print ("{0:24} {1:32} {2:32} {3:5}".format("","|"+operation, "|"+k,"|"+str(dic[k])))
			print_()
			vector_cryptousage = 1
	fw.write("sum_cryptousage: %s\n" % str(len(keys)))
# print DexClass initializations
if load.has_key('dexclass'):
	dexclass = load['dexclass']
	keys = dexclass.keys()
	keys.sort()
	if len(keys) > 0:
		print ("{0:^36} {1:32}".format("\033[1;48mDexClassLoader:\033[1;m", "|[Path]")) 
		printtt_()
		for key in keys:
		    temp = dexclass[key]
		    try:
			print ("{0:24} {1:32}".format("", "|"+temp['path']))	   
		    except ValueError:
			pass
		    except KeyError:
			pass
		print_()
		vector_dexclass = 1
	fw.write("sum_dexclass: %s\n" % str(len(keys)))
# print registered broadcast receivers
if load.has_key('recvsaction'):
	recvsaction = load['recvsaction']
	if len(recvsaction) > 0:
		print ("{0:^36} {1:32} {2:32}".format("\033[1;48mBroadcast receivers:\033[1;m", "|[Receiver]", "|[Action]")) 
		printtt_()
		for recv in recvsaction:
		    if len(recv) >= 32:
			print ("{0:24} {1:32} {2:32}".format("", "|"+recv[:28]+"...","|"+recvsaction[recv][:25])+'...')
		    else:
			print ("{0:24} {1:32} {2:32}".format("", "|"+recv, "|"+recvsaction[recv][:25])+'...')
		print_()
		vector_recvsaction = 1
	fw.write("sum_recvsaction: %s\n" % len(recvsaction))
# list started services
if load.has_key('servicestart'):
	servicestart = load['servicestart']
	keys = servicestart.keys()
	keys.sort()
	if len(keys) > 0:
		print ("{0:^36} {1:32}".format("\033[1;48mStarted services:\033[1;m", "|[Class]")) 
		printtt_()
		for key in keys:
		    temp = servicestart[key]
		    print ("{0:24} {1:32}".format("", "|"+temp['name']))
		print_()
		vector_servicestart = 1
	fw.write("sum_servicestart: %s\n" % str(len(keys)))
# print enforced permissions
if load.has_key('enfperm'):
	enfperm = load['enfperm']
	if len(enfperm) > 0:
		print ("{0:^36} {1:32}".format("\033[1;48mEnforced permissions:\033[1;m", "|[Permisson]")) 
		printtt_()
		for perm in enfperm:
		    print ("{0:24} {1:32}".format("", "|"+perm))
		print_()
		vector_enfperm = 1
	fw.write("sum_enfperm: %s\n" % str(len(enfperm)))

# Print data leaks
if load.has_key('dataleaks'):
	dataleaks = load['dataleaks']
	keys = dataleaks.keys()
	keys.sort()
	num_network = num_sms = num_file = 0
	if len(keys) > 0:
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
		print_()
		vector_dataleaks = 1
	fw.write("sum_dataleaks: %s\n" % str(len(keys)))

# Print sent SMSs
if load.has_key('sendsms'):
	sendsms = load['sendsms']
	keys = sendsms.keys()
	keys.sort()
	if len(keys) > 0:
		print ("{0:^36} {1:32} {2:32}".format("\033[1;48mSent SMS:\033[1;m", "|[Number]", "|[Message]")) 
		printtt_()
		for key in keys:
		    temp = sendsms[key]
		    try:
			if len(temp['number']) >= 32:
			    print ("{0:^24} {1:32} {2:32}".format("", "|"+temp['number'][:28]+"...","|"+temp['message']))
			else:
			    print ("{0:^24} {1:32} {2:32}".format("", "|"+temp['number'],"|"+temp['message']))	
		    except ValueError:
			pass
		    except KeyError:
			pass
		print_()
		vector_sendsms = 1
	fw.write("sum_sendsms: %s\n" % str(len(keys)))
# Print phone calls
if load.has_key('phonecalls'):
	phonecalls = load['phonecalls']
	keys = phonecalls.keys()
	keys.sort()
	if len(keys) > 0:
		print ("{0:^36} {1:32}".format("\033[1;48mPhone calls:\033[1;m", "|[Number]")) 
		printtt_()
		for key in keys:
		    temp = phonecalls[key]
		    try:
			print ("{0:24} {1:32}".format("", "|"+temp['number']))
		    except ValueError:
			pass
		    except KeyError:
			pass
		print_()
		vector_phonecalls = 1
	fw.write("sum_phonecalls: %s\n" % str(len(keys)))

fw.close()
f.close()
'''
vector = [vector_fileRead,vector_fileWrite,vector_opennet,vector_recvnet , vector_sendnet , vector_cryptousage , vector_dexclass , vector_recvsaction , vector_servicestart , vector_enfperm , vector_dataleaks, vector_sendsms , vector_phonecalls]

os.chdir("/home/myw/DroidBox_4.1.1/model")
clf = joblib.load('lr.model')
  

#print(clf.feature_importances_)  
  
test_data = []
test_data.append(vector)  
x = np.array(test_data)


answer = clf.predict(x) 
print "\n"
#print (answer) #<type 'numpy.ndarray'>

sum_file = open("/home/myw/DroidBox_4.1.1/result.txt","a")
if  answer[0]==1 :
	print apk_name+":malware"
	sum_file.write(apk_name+':malware\n')
else:
	print apk_name+":benign"
	sum_file.write(apk_name+':benign\n')
sum_file.close()
'''
