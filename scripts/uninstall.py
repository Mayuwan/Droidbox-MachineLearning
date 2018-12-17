import sys
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice

apkName = sys.argv[1]
package = sys.argv[2]
activity = sys.argv[3]

device = None

while device == None:
	try:
		#print("Waiting for the device...")
		device = MonkeyRunner.waitForConnection(3)
	except:
		pass

device.removePackage (package)
print ('removed success')
