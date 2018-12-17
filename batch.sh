#!/bin/bash

time=15
path_apk="/home/myw/DroidBox_4.1.1/APK/apk"
path_script="/home/myw/DroidBox_4.1.1/scripts"
path_txt="/home/myw/DroidBox_4.1.1/APK/apk-txt"
path_json="/home/myw/DroidBox_4.1.1/APK/apk-json"



pwd

for i in $path_apk/*apk
do
	OLD_IFS="$IFS" 
	IFS="/" 
	arr=($i)
	IFS="$OLD_IFS" 
	len=${#arr[*]}
	
	apk_name=${arr[$len-1]}
	apkjsonName=$apk_name'.json'
	json_name=${path_json}'/'$apkjsonName

	cd $path_json

	if test -e $json_name
	then
		echo "the $apk_name has been analysed"
		python $path_script/single_predict_result.py $apkjsonName $path_json
	else
		echo -e "\n\n\nFile: $i"
		python $path_script/droidbox.py "$i" $time $path_json $path_script $path_txt
	fi
	

done
python $path_script/sum.py $path_txt

