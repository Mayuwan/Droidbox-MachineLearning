import os,json
import sys
#from __future__ import division
Const_Image_Format = [".txt"]
class FileFilt:
    fileList = [""]
    counter = 0
    def __init__(self):
        pass
    def FindFile(self,dirr,filtrate = 1):
        global Const_Image_Format
        for s in os.listdir(dirr):
	    #print s
            newDir = os.path.join(dirr,s)
            if os.path.isfile(newDir):
                if filtrate:
                        if newDir and(os.path.splitext(newDir)[1] in Const_Image_Format):
                            self.fileList.append(newDir)
                            self.counter+=1
                else:
                    self.fileList.append(newDir)
                    self.counter+=1
 
if __name__ == "__main__":
	sum_benign=0
	sum_malware=0
	sum_fileRead = sum_fileWrite = sum_opennet = sum_recvnet = sum_sendnet = sum_cryptousage = sum_dexclass = sum_recvsaction = sum_servicestart = sum_enfperm = sum_dataleaks = sum_sendsms = sum_phonecalls =total_behaviors= 0
        b = FileFilt()
	#print sys.argv[1]
        b.FindFile(dirr = sys.argv[1])
        #print(b.counter)
	apk_num_fileRead = 0
	apk_num_fileWrite = apk_num_opennet = apk_num_recvnet = apk_num_sendnet = apk_num_cryptousage = apk_num_dexclass = apk_num_recvsaction = apk_num_servicestart = apk_num_enfperm = apk_num_dataleaks = apk_num_sendsms = apk_num_phonecalls = 0
        for k in b.fileList:
            #print k
	    vector_fileRead = vector_fileWrite = vector_opennet = vector_recvnet = vector_sendnet = vector_cryptousage = vector_dexclass = vector_recvsaction = vector_servicestart = vector_enfperm = vector_dataleaks= vector_sendsms = vector_phonecalls = 0
	    if os.path.exists(k):
		f = open(k,'r')
		for line in f:
		    if line.find('sum_fileRead') >= 0 and int(line.split(':')[1]) > 0:
			sum_fileRead = sum_fileRead + int(line.split(':')[1])
			apk_num_fileRead = apk_num_fileRead + 1 
			vector_fileRead = 1
		    elif line.find('sum_fileWrite') >= 0 and int(line.split(':')[1]) > 0:
			sum_fileWrite = sum_fileWrite + int(line.split(':')[1])
			apk_num_fileWrite = apk_num_fileWrite + 1
			vector_fileWrite = 1
		    elif line.find('sum_opennet') >= 0 and int(line.split(':')[1]) > 0:
			sum_opennet = sum_opennet + int(line.split(':')[1])
			apk_num_opennet = apk_num_opennet + 1
			vector_opennet = 1
		    elif line.find('sum_recvnet') >= 0 and int(line.split(':')[1]) > 0:
			sum_recvnet = sum_recvnet + int(line.split(':')[1])
			apk_num_recvnet =apk_num_recvnet + 1
			vector_recvnet = 1
		    elif line.find('sum_sendnet') >= 0 and int(line.split(':')[1]) > 0:
			sum_sendnet = sum_sendnet + int(line.split(':')[1])
			apk_num_sendnet =apk_num_sendnet + 1
			vector_sendnet = 1
		    elif line.find('sum_cryptousage') >= 0 and int(line.split(':')[1]) > 0:
			sum_cryptousage = sum_cryptousage + int(line.split(':')[1])
			apk_num_cryptousage = apk_num_cryptousage + 1
			vector_cryptousage = 1
		    elif line.find('sum_dexclass') >= 0 and int(line.split(':')[1]) > 0:
			sum_dexclass = sum_dexclass + int(line.split(':')[1])
			apk_num_dexclass =apk_num_dexclass + 1
			vector_dexclass = 1
		    elif line.find('sum_recvsaction') >= 0 and int(line.split(':')[1]) > 0:
			sum_recvsaction = sum_recvsaction + int(line.split(':')[1])
			apk_num_recvsaction = apk_num_recvsaction + 1
			vector_recvsaction = 1
		    elif line.find('sum_servicestart') >= 0 and int(line.split(':')[1]) > 0:
			sum_servicestart = sum_servicestart + int(line.split(':')[1])
			apk_num_servicestart = apk_num_servicestart + 1
			vector_servicestart = 1
		    elif line.find('sum_enfperm') >= 0 and int(line.split(':')[1]) > 0:
			sum_enfperm = sum_enfperm + int(line.split(':')[1])
			apk_num_enfperm = apk_num_enfperm + 1
			vector_enfperm = 1
		    elif line.find('sum_dataleaks') >= 0 and int(line.split(':')[1]) > 0:
			sum_dataleaks = sum_dataleaks + int(line.split(':')[1])
			apk_num_dataleaks = apk_num_dataleaks + 1
			vector_dataleaks = 1
		    elif line.find('sum_sendsms') >= 0 and int(line.split(':')[1]) > 0:
			sum_sendsms = sum_sendsms + int(line.split(':')[1])
			apk_num_sendsms = apk_num_sendsms + 1
			vector_sendsms = 1
		    elif line.find('sum_phonecalls') >= 0 and int(line.split(':')[1]) > 0:
			sum_phonecalls = sum_phonecalls + int(	line.split(':')[1])
			apk_num_phonecalls = apk_num_phonecalls + 1
			vector_phonecalls = 1
		f.close()
		'''
		trainset = open("TrainSet.txt","a")
		apk = os.path.splitext(os.path.split(k)[1])[0]
		benign = 'benign'
		malware = 'malware'
		trainset.write(apk+":"+str(vector_fileRead) +' '+ str(vector_fileWrite) +' '+ str(vector_opennet) +' '+ str(vector_recvnet) +' '+ str(vector_sendnet) +' '+ str(vector_cryptousage) +' '+ str(vector_dexclass) +' '+ str(vector_recvsaction) +' '+ str(vector_servicestart) +' '+ str(vector_enfperm) +' '+ str(vector_dataleaks)+' '+ str(vector_sendsms) +' '+ str(vector_phonecalls) +'\n')
		trainset.close()
		'''
	total_behaviors = sum_fileRead + sum_fileWrite + sum_opennet + sum_recvnet + sum_sendnet + sum_cryptousage + sum_dexclass + sum_recvsaction + sum_servicestart + sum_enfperm + sum_dataleaks + sum_sendsms + sum_phonecalls
	total_float = float(total_behaviors)

	apk_num_float = float(len(b.fileList))
	print '\n'
	print '{:*^120}'.format("\033[1;48mSummary Dynamic Analysis Results\033[1;m")
	print '\n'		
	#print sum table
	print ("{0:^44} {1:28} {2:28} {3:28} {4:28}".format("\033[1;48m[Behavior]\033[1;m", "\033[1;48m[Number]\033[1;m","\033[1;48m[Proportion]\033[1;m","\033[1;48m[APK_Number]\033[1;m","\033[1;48m[APK_Number_Proportion]\033[1;m"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mFile Read:\033[1;m", str(sum_fileRead),str(round(sum_fileRead/total_float,4)*100)+"%",str(apk_num_fileRead),str(round(apk_num_fileRead/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mFile Write:\033[1;m", str(sum_fileWrite),str(round(sum_fileWrite/total_float,4)*100)+"%",str(apk_num_fileWrite),str(round(apk_num_fileWrite/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mOpened connections:\033[1;m", str(sum_opennet),str(round(sum_opennet/total_float,4)*100)+"%",str(apk_num_opennet),str(round(apk_num_opennet/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mIncoming traffic:\033[1;m", str(sum_recvnet),str(round(sum_recvnet/total_float,4)*100)+"%",str(apk_num_recvnet),str(round(apk_num_recvnet/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mOutgoing traffic:\033[1;m", str(sum_sendnet),str(round(sum_sendnet/total_float,4)*100)+"%" ,str(apk_num_sendnet),str(round(apk_num_sendnet/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mCrypto API activities\033[1;m", str(sum_cryptousage),str(round(sum_cryptousage/total_float,4)*100)+"%" ,str(apk_num_cryptousage),str(round(apk_num_cryptousage/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mDexClassLoader:\033[1;m", str(sum_dexclass),str(round(sum_dexclass/total_float,4)*100)+"%",str(apk_num_dexclass),str(round(apk_num_dexclass/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mBroadcast receivers:\033[1;m", str(sum_recvsaction),str(round(sum_recvsaction/total_float,4)*100)+"%" ,str(apk_num_recvsaction),str(round(apk_num_recvsaction/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mStarted services:\033[1;m", str(sum_servicestart),str(round(sum_servicestart/total_float,4)*100)+"%",str(apk_num_servicestart),str(round(apk_num_servicestart/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mEnforced permissions:\033[1;m", str(sum_enfperm),str(round(sum_enfperm/total_float,4)*100)+"%",str(apk_num_enfperm),str(round(apk_num_enfperm/apk_num_float,4)*100)+"%" ))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mInformation leakage:\033[1;m", str(sum_dataleaks),str(round(sum_dataleaks/total_float,4)*100)+"%",str(apk_num_dataleaks),str(round(apk_num_dataleaks/apk_num_float,4)*100)+"%" ))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mSent SMS:\033[1;m", str(sum_sendsms),str(round(sum_sendsms/total_float,4)*100)+"%",str(apk_num_sendsms),str(round(apk_num_sendsms/apk_num_float,4)*100)+"%"))
	print ("{0:^44} {1:16} {2:16} {3:16} {4:16}".format("\033[1;48mPhone calls:\033[1;m", str(sum_phonecalls),str(round(sum_phonecalls/total_float,4)*100)+"%",str(apk_num_phonecalls),str(round(apk_num_phonecalls/apk_num_float,4)*100)+"%") )
	
	result = open("/home/myw/DroidBox_4.1.1/classify.txt","r")
	for line in result:
	    s=line.strip().split(":")
    	    if s[1] == 'benign':
	    	sum_benign +=1
            elif s[1] == 'malware':
		sum_malware +=1
	result.close()
	#print "benign:"+str(sum_benign)
	#print "malware:"+str(sum_malware)
	apk_num = float(b.counter)
	
	print "\n"
	print '{:*^120}'.format("\033[1;48mSummary Dynamic Analysis Sort Results\033[1;m")
	print ("{0:^44} {1:32} {2:32}".format("\033[1;48mcatalogue:\033[1;m","number","proportion"))
	print ("{0:^44} {1:32} {2:32}".format("\033[1;48mbenign:\033[1;m",str(sum_benign),str(round(sum_benign/apk_num,4)*100)+'%'))
	print ("{0:^44} {1:32} {2:32}".format("\033[1;48mmalware:\033[1;m",str(sum_malware),str(round(sum_malware/apk_num,4)*100)+'%'))
	
    
