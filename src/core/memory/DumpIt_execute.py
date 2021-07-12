# coding=utf-8
import subprocess
import os


def Dumpit_run():
    subprocess.SW_HIDE = 1
    r = subprocess.Popen(['..\..\..\program\DumpIt\DumpIt.exe', 'Y'], shell=True).wait()

    #r = subprocess.call(['runas', '/user:Administrator', 'C:\WINDOWS\system32\cmd.exe'], shell=True)

    if r==1:
        print('running error')
    else:
        print('running success')