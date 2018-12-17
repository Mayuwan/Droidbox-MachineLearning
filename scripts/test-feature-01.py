import os,json
keyalgo_list_num = algo_list_num = sendsms_list_num = dexclass_list_num = opennet_list_num = recvnet_list_num = sendnet_list_num = 0
dataleaks_list_num = servicestart_list_num = fileread_list_num = filewrite_list_num = receiver_list_num = action_list_num =tag_list_num= 0

keyalgo_list =[] 
algo_list =[]
sendsms_list = []
dexclass_list= []
opennet_list = []
recvnet_list =[] 
sendnet_list = []
dataleaks_list = []
servicestart_list = []
fileread_list = []
filewrite_list = []
receiver_list = []
action_list = []

vector_list = []
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
def allBehavoirs():
	f= open("/home/myw/DroidBox_4.1.1/num.txt","r")
	for line in f:
		temp = line.split(':')
		if temp[0] == 'keyalgo_list':
			keyalgo_list_num = int(temp[1])
		elif temp[0] == 'algo_list':
			algo_list_num = int(temp[1])
		elif temp[0] == 'sendsms_list':
			sendsms_list_num = int(temp[1])
		elif temp[0] == 'dexclass_list':
			dexclass_list_num = int(temp[1])
		elif temp[0] == 'opennet_list':
			opennet_list_num = int(temp[1])
		elif temp[0] == 'recvnet_list':
			recvnet_list_num = int(temp[1])
		elif temp[0] == 'sendnet_list':
			sendnet_list_num = int(temp[1])
		elif temp[0] == 'dataleaks_list':
			dataleaks_list_num = int(temp[1])
		elif temp[0] == 'servicestart_list':
			servicestart_list_num = int(temp[1])
		elif temp[0] == 'fileread_list':
			fileread_list_num = int(temp[1])
		elif temp[0] == 'filewrite_list':
			filewrite_list_num = int(temp[1])
		elif temp[0] == 'receiver_list':
			receiver_list_num = int(temp[1])
		elif temp[0] == 'action_list':
			action_list_num = int(temp[1])
	f.close()
	
	f= open("/home/myw/DroidBox_4.1.1/feature-list.txt","r")
	s = f.read()
	li = s.strip().split(',')
	for i in range(len(li)):
		li[i] = li[i].strip().replace("'",'')
	r2 = keyalgo_list_num + algo_list_num
	r3 = r2 + sendsms_list_num 
	r4 = r3 + dexclass_list_num 
	r5 = r4 + opennet_list_num 
	r6 = r5 + recvnet_list_num
	r7 = r6 + sendnet_list_num
	r8 = r7 + dataleaks_list_num
	r9 = r8 + servicestart_list_num
	r10 = r9 + fileread_list_num
	r11 = r10 + filewrite_list_num
	r12 = r11 + receiver_list_num
	r13 = r12 + action_list_num

	for j in range(len(li)):
		if j < keyalgo_list_num:
			keyalgo_list.append(li[j])
		elif keyalgo_list_num <= j and j < r2:
			algo_list.append(li[j])
		elif r2 <= j and j < r3:
			sendsms_list.append(li[j])
		elif r3 <= j and j < r4:
			dexclass_list.append(li[j])
		elif r4 <= j and j < r5:
			opennet_list.append(li[j])
		elif r5 <= j and j < r6:
			recvnet_list.append(li[j])
		elif r6 <= j and j < r7:
			sendnet_list.append(li[j])
		elif r7 <= j < r8:
			dataleaks_list.append(li[j])
		elif r8 <= j < r9:
			servicestart_list.append(li[j])
		elif r9 <= j < r10:
			fileread_list.append(li[j])
		elif r10 <= j < r11:
			filewrite_list.append(li[j])
		elif r11 <= j < r12:
			receiver_list.append(li[j])
		elif r12 <= j < r13:
			action_list.append(li[j])
	tags = []
	for i in range(len(dataleaks_list)):
		temp = dataleaks_list[i].split(':')
		tags.append(temp[0])
	s = list(set(tags))
	tag_list.extend(s)
	#print keyalgo_list_num ,algo_list_num , sendsms_list_num ,dexclass_list_num , opennet_list_num , recvnet_list_num , sendnet_list_num , dataleaks_list_num , servicestart_list_num , fileread_list_num , filewrite_list_num ,receiver_list_num, action_list_num 
	#print type(li),li
	#if 'eventsnooze' in li:
		#print "yes"
	f.close()
	
def testVector(dirr):
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
							keyalgo_lable[index] = 1
					vector.extend(keyalgo_lable)	
	
					algo_tempdic = statistics(algo_temp)
					for key in algo_tempdic.keys():
						if key in algo_list:
							index = algo_list.index(key)
							algo_lable[index] = 1
					vector.extend(algo_lable)
			else:
				vector.extend(keyalgo_lable)
				vector.extend(algo_lable)
		#print vector
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
						sendsms_lable[index] = 1
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
						dexclass_lable[index] = 1
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
						opennet_lable[index] = 1
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
						recvnet_lable[index] = 1
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
						sendnet_lable[index] = 1
				vector.extend(sendnet_lable)	
			else:
				vector.extend(sendnet_lable)	
		
		if load.has_key('dataleaks'):
			dataleaks = load['dataleaks']
			keys = dataleaks.keys()
			keys.sort()
			dataleaks_lable = [0] * len(dataleaks_list)
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
						dataleaks_lable[index] = 1	
 				for key in Filetag_tempdic.keys():
					if key in tag_list:
						index = tag_list.index(key) + len(tag_list) * 1
						dataleaks_lable[index] = 1	
				for key in SMStag_tempdic.keys():
					if key in tag_list:
						index = tag_list.index(key) + len(tag_list) * 2
						dataleaks_lable[index] = 1	
				
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
						servicestart_lable[index] = 1
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
							fileread_temp.append(temp['path'].split('/')[-1])
					except ValueError:
						pass
					except KeyError:
						pass
			
				for key in keys:
					temp = fdaccess[key]
					try:
						if temp['operation'] == 'write':
							filewrite_temp.append(temp['path'].split('/')[-1])
					except ValueError:
						pass
					except KeyError:
						pass
				fileread_tempdic = statistics(fileread_temp)
				for key in fileread_tempdic.keys():
					if key in fileread_list:
						index = fileread_list.index(key)
						fileread_lable[index] = 1
				vector.extend(fileread_lable)	
				
				filewrite_tempdic = statistics(filewrite_temp)
				for key in filewrite_tempdic.keys():
					if key in filewrite_list:
						index = filewrite_list.index(key)
						filewrite_lable[index] = 1
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
						receiver_lable[index] = 1
				vector.extend(receiver_lable)	
				
				action_tempdic = statistics(action_temp)
				for key in action_tempdic.keys():
					if key in action_list:
						index = action_list.index(key)
						action_lable[index] = 1
				vector.extend(action_lable)	
			else:
				vector.extend(receiver_lable)	
				vector.extend(action_lable)	
		#print len(vector)
		
		benign = ['benign']
		malware = ['malware']
		vector.extend(malware)
		fi = open("/home/myw/DroidBox_4.1.1/test_feature_01.txt",'a')
		value = str(vector)
		value = value.replace('[','')
		value = value.replace(']','')
		fi.write(value+'\n')
		fi.close()
		
		f.close()
if __name__ == "__main__":
	allBehavoirs()
	testVector("/media/myw/Windows8_OS/testAPK/malwareAPK/test-apk-malware-json")
	
