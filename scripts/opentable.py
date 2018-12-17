#-*- coding:GBK -*-
import subprocess,os
from subprocess import call, PIPE, Popen

filename="/home/myw/DroidBox_4.1.1/APK/apk-json/air.com.golfchannel.gcliveextra-4200626.apk.json"
re = Popen( ["/usr/bin/python2.7","data.py",filename], stdout = PIPE,stderr =PIPE, cwd=os.path.dirname(os.path.realpath(__file__)))
out,err = re.communicate()


print out
print "err:"+err
#print "returnNumber"+re.stdout.read()
#print re.returncode
