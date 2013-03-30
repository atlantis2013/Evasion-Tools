import yara
import os
import glob
import shutil

def mycallback(data):
    if(len(data["strings"]) != 0):
        print data
    yara.CALLBACK_CONTINUE


rules = yara.compile('C:\Documents and Settings\Administrator\Desktop\improved_vmdetect.yar')

os.chdir("C:\Documents and Settings\Administrator\Desktop\Malwares")
for files in glob.glob("*.vir"):
    matches = rules.match(files)
    if (len(matches)!=0):
        path = os.path.join("C:\Documents and Settings\Administrator\Desktop\Malwares", files)
        print path
        shutil.move(path, 'C:\Documents and Settings\Administrator\Desktop\checks')
