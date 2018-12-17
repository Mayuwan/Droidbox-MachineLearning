# -*- coding: utf-8 -*-
import sys,os,json

algo_keyalgo = list()
algo = list()
sendsms_number = list()
dexload_path = list()
fileread_path = list()
filewrite_path = list()
tag_all = list()
opennets = list()
recvnets = list()
sendnets = list()
servicestarts = list()
receivers = list()
actions = list()

vector_list = []

keyalgo_list = []
algo_list = []
sendsms_list = []
dexclass_list = []
opennet_list =[]
recvnet_list = []
sendnet_list = []
dataleaks_list = []
servicestart_list = []
fileread_list = []
filewrite_list = []
receiver_list = []
action_list = []
tag_list = []
def statistics(algo):
	if len(algo) >= 0:
		algo.sort()
		dic = {}
		i = 0
		while i<len(algo):
			dic[algo[i]] = algo.count(algo[i])#key:algorithm   value:count
			i = i + dic[algo[i]]
	return dic

def allBehavoirs(dirr):
	os.chdir(dirr)
	for s in os.listdir(dirr):
		f = open(s, 'r')
		load = json.load( f )
		#start to statistics all of the behaviors
		if load.has_key('cryptousage'):
			cryptousage = load['cryptousage']
			keys = cryptousage.keys()
			keys.sort()
			if len(keys) > 0:
					for key in keys:                                                               
						temp = cryptousage[key]
						try:
							if temp['operation'] == 'keyalgo':
								algorithm = temp['algorithm'].encode("utf-8")
								algo_keyalgo.append(algorithm)
							else:
								algorithm = temp['algorithm'].encode("utf-8")
								algo.append(algorithm)
						except ValueError:
							pass
						except KeyError:
							pass
		if load.has_key('sendsms'):
			sendsms = load['sendsms']
			keys = sendsms.keys()
			keys.sort()
			if len(keys) > 0:
				for key in keys:
					temp = sendsms[key]
					try:
						number = temp['number'].encode("utf-8")
						sendsms_number.append(number)
					except ValueError:
						pass
					except KeyError:
						pass
		if load.has_key('dexclass'):
			dexclass = load['dexclass']
			keys = dexclass.keys()
			keys.sort()
			if len(keys) > 0:
				for key in keys:
					temp = dexclass[key]
					try:
						path = temp['path'].encode("utf-8")
						dexload_path.append(path)
					except ValueError:
						pass
					except KeyError:
						pass	
		if load.has_key('opennet'):# ip:host
			opennet = load['opennet']
			keys = opennet.keys()
			keys.sort()
			if len(keys) != 0:
				for key in keys:
					temp = opennet[key]
					try:
						desthost = temp['desthost'].encode("utf-8")
						destport = temp['destport'].encode("utf-8")
						opennets.append(desthost+':'+destport)
					except ValueError:
						pass
					except KeyError:
						pass
		if load.has_key('recvnet'):
			recvnet = load['recvnet']
			keys = recvnet.keys()
			keys.sort()
			if len(keys) != 0:
				for key in keys:
					temp = recvnet[key]
					try:
						host = temp['host'].encode("utf-8")
						port = temp['port'].encode("utf-8")
						recvnets.append(host+':'+port)
					except ValueError:
						pass
					except KeyError:
						pass
		if load.has_key('sendnet'):
			sendnet = load['sendnet']
			keys = sendnet.keys()
			keys.sort()
			if len(keys) != 0:
				for key in keys:
					temp = sendnet[key]
					try:
						desthost = temp['desthost'].encode("utf-8")
						destport = temp['destport'].encode("utf-8")
						sendnets.append(desthost+':' +destport)
					except ValueError:
						pass
					except KeyError:
						pass
		if load.has_key('dataleaks'):
			dataleaks = load['dataleaks']
			keys = dataleaks.keys()
			keys.sort()
			num_network = num_sms = num_file = 0
			if len(keys) > 0:
				for key in keys:
					temp = dataleaks[key]
					try: 
						for i in temp['tag']:
							temptag = i.encode("utf-8")
							tag_all.append(temptag)
					except ValueError:
						pass
					except KeyError:
						pass
		if load.has_key('servicestart'):
			servicestart = load['servicestart']
			keys = servicestart.keys()
			keys.sort()
			if len(keys) > 0:
				for key in keys:
					temp = servicestart[key]
					try:
						name = temp['name'].encode("utf-8")
						servicestarts.append(name)
					except ValueError:
						pass
					except KeyError:
						pass
		if load.has_key('fdaccess'):
			fdaccess = load['fdaccess']
			keys = fdaccess.keys()
			keys.sort()
			if len(keys) != 0:
				for key in keys:
					temp = fdaccess[key]
					try:
						if temp['operation'] == 'read':
							path = temp['path'].encode("utf-8")
							fileread_path.append(temp['path'].split('/')[-1])##statistics(servicestarts)  remove the same  786
					except ValueError:
						pass
					except KeyError:
						pass
			
				for key in keys:
					temp = fdaccess[key]
					try:
						if temp['operation'] == 'write':
							path = temp['path'].encode("utf-8")
							filewrite_path.append(path.split('/')[-1])#statistics(servicestarts)  remove the same  2508
					except ValueError:
						pass
					except KeyError:
						pass
		
		if load.has_key('recvsaction'):
			recvsaction = load['recvsaction']
			if len(recvsaction) > 0:
				for recv in recvsaction:
					r = recv.encode("utf-8")
					rs = recvsaction[recv].encode("utf-8")
					receivers.append(r) 
					actions.append(rs)
		f.close()
def cryptoList():
	e = list(set(algo_keyalgo))
	#print e
	for i in range(len(e)):
		keyalgo_list.append(e[i])
	del algo_keyalgo[:]
	vector_list.extend(keyalgo_list)

	s = list(set(algo))
	for i in range(len(s)):
		algo_list.append(s[i])
	del algo[:]
	vector_list.extend(algo_list)
def numberList():
	e = list(set(sendsms_number))
	del sendsms_number[:]
	for k in range(len(e)):
		sendsms_list.append(e[k])
	vector_list.extend(sendsms_list)
def dexclassList():
	e = list(set(dexload_path))
	del dexload_path[:]
	for k in range(len(e)):
		dexclass_list.append(e[k])
	vector_list.extend(dexclass_list)
def opennetList():
	e = list(set(opennets))
	del opennets[:]	
	for i in range(len(e)):
		opennet_list.append(e[i])
	vector_list.extend(opennet_list)
def recvnetList():
	e = list(set(recvnets))
	del recvnets[:]	
	for i in range(len(e)):
		recvnet_list.append(e[i])
	vector_list.extend(recvnet_list)
def sendnetList():
	e = list(set(sendnets))
	del sendnets[:]	
	for i in range(len(e)):
		sendnet_list.append(e[i])
	vector_list.extend(sendnet_list)
def dataleaksList():
	e = list(set(tag_all))
	dimension = [['a']*len(e)]*3
	del tag_all[:]
	for s in range(len(e)):
		tag_list.append(e[s])
	for i in range(3):
		for k in range(len(e)):
			dimension[i][k] = e[k]+':'+str(i)
			dataleaks_list.append(dimension[i][k])
	vector_list.extend(dataleaks_list)
def servicestartList():
	e = list(set(servicestarts))
	del servicestarts[:]	
	for i in range(len(e)):
		servicestart_list.append(e[i])
	vector_list.extend(servicestart_list)
def filepathList():
	e = list(set(fileread_path))
	for i in range(len(e)):
		fileread_list.append(e[i])
	del fileread_path[:]
	vector_list.extend(fileread_list)

	s = list(set(filewrite_path))
	for i in range(len(s)):
		filewrite_list.append(s[i])
	del filewrite_path[:]
	vector_list.extend(filewrite_list)
def recvsactionList():
	e = list(set(receivers))
	for i in range(len(e)):
		receiver_list.append(e[i])
	del receivers[:]
	vector_list.extend(receiver_list)

	s = list(set(actions))
	for i in range(len(s)):
		action_list.append(s[i])
	del actions[:]
	vector_list.extend(action_list)
def trainrVector(dirr):
	for s in os.listdir(dirr):
		os.chdir(dirr)
		f = open(s, 'r')
		load = json.load( f )
		vector = []
		#start to statistics all of the behaviors
		if load.has_key('cryptousage'):
			cryptousage = load['cryptousage']
			keys = cryptousage.keys()
			keys.sort()
			keyalgo_lable = [0] * len(keyalgo_list)
			algo_lable = [0] * len(algo_list)
			if len(keys) > 0:
					keyalgo_temp = []
					algo_temp = []
					for key in keys:                                                               
						temp = cryptousage[key]
						try:
							if temp['operation'] == 'keyalgo':
								keyalgo_temp.append(temp['algorithm'])
							else:
								algo_temp.append(temp['algorithm'])
						except ValueError:
							pass
						except KeyError:
							pass
					keyalgo_tempdic = statistics(keyalgo_temp)
					for key in keyalgo_tempdic.keys():
						if key in keyalgo_list:
							index = keyalgo_list.index(key)
							keyalgo_lable[index] = keyalgo_tempdic[key]
					vector.extend(keyalgo_lable)	
	
					algo_tempdic = statistics(algo_temp)
					for key in algo_tempdic.keys():
						if key in algo_list:
							index = algo_list.index(key)
							algo_lable[index] = algo_tempdic[key]
					vector.extend(algo_lable)
			else:
				vector.extend(keyalgo_lable)
				vector.extend(algo_lable)
		print vector
		if load.has_key('sendsms'):
			sendsms = load['sendsms']
			keys = sendsms.keys()
			keys.sort()
			sendsms_lable = [0] * len(sendsms_list)
			if len(keys) > 0:
				sendsms_temp = []
				for key in keys:
					temp = sendsms[key]
					try:
						sendsms_temp.append(temp['number'])
					except ValueError:
						pass
					except KeyError:
						pass
				sendsms_tempdic = statistics(sendsms_temp)
				for key in sendsms_tempdic.keys():
					if key in sendsms_list:
						index = sendsms_list.index(key)
						sendsms_lable[index] = sendsms_tempdic[key]
				vector.extend(sendsms_lable)	
			else:
				vector.extend(sendsms_lable)
			#print sendsms_lable
		
		if load.has_key('dexclass'):
			dexclass = load['dexclass']
			keys = dexclass.keys()
			keys.sort()
			dexclass_lable = [0] * len(dexclass_list)
			if len(keys) > 0:
				dexclass_temp = []
				for key in keys:
					temp = dexclass[key]
					try:
						dexclass_temp.append(temp['path'])
					except ValueError:
						pass
					except KeyError:
						pass
				dexclass_tempdic = statistics(dexclass_temp)
				for key in dexclass_tempdic.keys():
					if key in dexclass_list:
						index = dexclass_list.index(key)
						dexclass_lable[index] = dexclass_tempdic[key]
				vector.extend(dexclass_lable)
			else:
				vector.extend(dexclass_lable)	
			#print dexclass_lable
		
		if load.has_key('opennet'):# ip:host
			opennet = load['opennet']
			keys = opennet.keys()
			keys.sort()
			opennet_lable = [0] * len(opennet_list)
			if len(keys) != 0:
				opennet_temp = []
				for key in keys:
					temp = opennet[key]
					try:
						opennet_temp.append(temp['desthost'] + ':' + temp['destport'])
					except ValueError:
						pass
					except KeyError:
						pass
				opennet_tempdic = statistics(opennet_temp)
				for key in opennet_tempdic.keys():
					if key in opennet_list:
						index = opennet_list.index(key)
						opennet_lable[index] = opennet_tempdic[key]
				vector.extend(opennet_lable)	
			else:
				vector.extend(opennet_lable)	
		
		if load.has_key('recvnet'):
			recvnet = load['recvnet']
			keys = recvnet.keys()
			keys.sort()
			recvnet_lable = [0] * len(recvnet_list)
			if len(keys) != 0:
				recvnet_temp = []
				for key in keys:
					temp = recvnet[key]
					try:
						recvnet_temp.append(temp['host']+':'+ temp['port'])
					except ValueError:
						pass
					except KeyError:
						pass
				recvnet_tempdic = statistics(recvnet_temp)
				for key in recvnet_tempdic.keys():
					if key in recvnet_list:
						index = recvnet_list.index(key)
						recvnet_lable[index] = recvnet_tempdic[key]
				vector.extend(recvnet_lable)	
			else:
				vector.extend(recvnet_lable)	
		
		if load.has_key('sendnet'):
			sendnet = load['sendnet']
			keys = sendnet.keys()
			keys.sort()
			sendnet_lable = [0] * len(sendnet_list)
			if len(keys) != 0:
				sendnet_temp = []
				for key in keys:
					temp = sendnet[key]
					try:
						sendnet_temp.append(temp['desthost']+':'+ temp['destport'])
					except ValueError:
						pass
					except KeyError:
						pass
				sendnet_tempdic = statistics(sendnet_temp)
				for key in sendnet_tempdic.keys():
					if key in sendnet_list:
						index = sendnet_list.index(key)
						sendnet_lable[index] = sendnet_tempdic[key]
				vector.extend(sendnet_lable)	
			else:
				vector.extend(sendnet_lable)	
		
		if load.has_key('dataleaks'):
			dataleaks = load['dataleaks']
			keys = dataleaks.keys()
			keys.sort()
			dataleaks_lable = [0] * len(tag_list)*3
			if len(keys) > 0:
				Networktag_temp = []
				Filetag_temp = []
				SMStag_temp = []
				for key in keys:
					temp = dataleaks[key]
					try: 
						if temp['sink'] == 'Network':
							Networktag_temp.extend(temp['tag'])
						if temp['sink'] == 'File':
							Filetag_temp.extend(temp['tag'])
						if temp['sink'] == 'SMS':
							SMStag_temp.extend(temp['tag'])
					except ValueError:
						pass
					except KeyError:
						pass
						dataleaks_list
				Networktag_tempdic = statistics(Networktag_temp)
				Filetag_tempdic= statistics(Filetag_temp)
				SMStag_tempdic = statistics(SMStag_temp)
				for key in Networktag_tempdic.keys():
					if key in tag_list:
						index = tag_list.index(key) + len(tag_list) * 0
						dataleaks_lable[index] = Networktag_tempdic[key]	
 				for key in Filetag_tempdic.keys():
					if key in tag_list:
						index = tag_list.index(key) + len(tag_list) * 1
						dataleaks_lable[index] = Filetag_tempdic[key]	
				for key in SMStag_tempdic.keys():
					if key in tag_list:
						index = tag_list.index(key) + len(tag_list) * 2
						dataleaks_lable[index] = SMStag_tempdic[key]	
				
				vector.extend(dataleaks_lable)	
			else:
				vector.extend(dataleaks_lable)	
			
		if load.has_key('servicestart'):
			servicestart = load['servicestart']
			keys = servicestart.keys()
			keys.sort()
			servicestart_lable = [0] * len(servicestart_list)
			if len(keys) > 0:
				servicestart_temp = []
				for key in keys:
					temp = servicestart[key]
					try:
						servicestart_temp.append(temp['name'])#statistics(servicestarts)  remove the same
					except ValueError:
						pass
					except KeyError:
						pass
				servicestart_tempdic = statistics(servicestart_temp)
				for key in servicestart_tempdic.keys():
					if key in servicestart_list:
						index = servicestart_list.index(key)
						servicestart_lable[index] = servicestart_tempdic[key]
				vector.extend(servicestart_lable)	
			else:
				vector.extend(servicestart_lable)	
	
		if load.has_key('fdaccess'):
			fdaccess = load['fdaccess']
			keys = fdaccess.keys()
			keys.sort()
			fileread_lable = [0]*len(fileread_list)
			filewrite_lable = [0]*len(filewrite_list)
			if len(keys) != 0:
				fileread_temp = []
				filewrite_temp = []
				for key in keys:
					temp = fdaccess[key]
					try:
						if temp['operation'] == 'read':
							fileread_temp.append(temp['path'].split('/')[-1])##statistics(servicestarts)  remove the same  786
					except ValueError:
						pass
					except KeyError:
						pass
			
				for key in keys:
					temp = fdaccess[key]
					try:
						if temp['operation'] == 'write':
							filewrite_temp.append(temp['path'].split('/')[-1])#statistics(servicestarts)  remove the same  2508
					except ValueError:
						pass
					except KeyError:
						pass
				fileread_tempdic = statistics(fileread_temp)
				for key in fileread_tempdic.keys():
					if key in fileread_list:
						index = fileread_list.index(key)
						fileread_lable[index] = fileread_tempdic[key]
				vector.extend(fileread_lable)	
				
				filewrite_tempdic = statistics(filewrite_temp)
				for key in filewrite_tempdic.keys():
					if key in filewrite_list:
						index = filewrite_list.index(key)
						filewrite_lable[index] = filewrite_tempdic[key]
				vector.extend(filewrite_lable)	
			else:
				vector.extend(fileread_lable)	
				vector.extend(filewrite_lable)	
		
		if load.has_key('recvsaction'):
			recvsaction = load['recvsaction']
			receiver_lable  = [0] * len(receiver_list)
			action_lable = [0] * len(action_list)
			if len(recvsaction) > 0:
				receiver_temp = []
				action_temp = []
				for recv in recvsaction:
					receiver_temp.append(recv) 
					action_temp.append(recvsaction[recv])
					
				receiver_tempdic = statistics(receiver_temp)
				for key in receiver_tempdic.keys():
					if key in receiver_list:
						index = receiver_list.index(key)
						receiver_lable[index] = receiver_tempdic[key]
				vector.extend(receiver_lable)	
				
				action_tempdic = statistics(action_temp)
				for key in action_tempdic.keys():
					if key in action_list:
						index = action_list.index(key)
						action_lable[index] = action_tempdic[key]
				vector.extend(action_lable)	
			else:
				vector.extend(receiver_lable)	
				vector.extend(action_lable)	
		
		benign = ['benign']
		malware = ['malware']
		vector.extend(malware)
		fi = open("/home/myw/DroidBox_4.1.1/train_vector.txt",'a')
		value = str(vector)
		value = value.replace('[','')
		value = value.replace(']','')
		fi.write(value+'\n')
		fi.close()
		
		f.close()

if __name__ == "__main__":
	allBehavoirs("/media/myw/Windows8_OS/trainJSON")
	
	cryptoList()
	#print len(keyalgo_list)#8
	#print len(algo_list)#12
	numberList()
	#print len(sendsms_list)#24
	dexclassList()
	#print len(dexclass_list)#1543
	opennetList()
	#print len(opennet_list)#834
	recvnetList()
	#print len(recvnet_list)#333
	sendnetList()
	#print len(sendnet_list)#347
	dataleaksList()
	#print len(dataleaks_list)#18
	servicestartList()
	#print len(servicestart_list)#322
	filepathList()
	#print len(fileread_list)#786
	#print len(filewrite_list)#2508
	recvsactionList()
	#print len(receiver_list)#2099
	#print len(action_list)#708
	
	#print len(vector_list)#9542
	#trainrVector("/media/myw/Windows8_OS/trainAPK/malwareAPK/malware_jsonFile")
	os.chdir("/home/myw/DroidBox_4.1.1")
	f = open('num.txt','w')
	f.write("keyalgo_list:" + str(len(keyalgo_list)) + '\n')
	f.write("algo_list:" + str(len(algo_list)) + '\n')
	f.write("sendsms_list:" + str(len(sendsms_list)) + '\n')
	f.write("dexclass_list:" + str(len(dexclass_list)) + '\n')
	f.write("opennet_list:" + str(len(opennet_list)) + '\n')
	f.write("recvnet_list:" + str(len(recvnet_list)) + '\n')
	f.write("sendnet_list:" + str(len(sendnet_list)) + '\n')
	f.write("dataleaks_list:" + str(len(dataleaks_list)) + '\n')
	f.write("servicestart_list:" + str(len(servicestart_list)) + '\n')
	f.write("fileread_list:" + str(len(fileread_list)) + '\n')
	f.write("filewrite_list:" + str(len(filewrite_list)) + '\n')
	f.write("receiver_list:" + str(len(receiver_list)) + '\n')
	f.write("action_list:" + str(len(action_list)) + '\n')
	#f.write("tag_list:" + str(len(tag_list)) + '\n')
	f.close()
	'''
	fil = open("feature-format.txt","w")
	pre = str(vector_list)
	pre = pre.replace('[','')
	pre = pre.replace(']','')
	fil.write(pre)
	#print pre
	fil.close()
	del vector_list[:]
	
	f = open('//home/myw/DroidBox_4.1.1/feature-list','r')
s=f.read()
print type(s),s
li = s.strip().split(',')
#li = list(s)
for i in range(len(li)):
	li[i] = li[i].strip().replace("'",'')
print type(li),li
if 'DES' in li:
	print 'ture'
else:
	print 'false' 
f.close()
	'''
