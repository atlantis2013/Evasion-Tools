for %%i in (C:\Malwares\*) do (
md logs
C:\pin\pin -t C:\GitHub\CP4101\ParanoidDetector\Debug\PinTool.dll -- %%i
ping 1.1.1.1 -n 1 -w 10000 >NUL
ParanoidDetector\Debug\GenerateReport.exe
ping 1.1.1.1 -n 1 -w 1000 >NUL
ren C:\GitHub\CP4101\logs %%~ni
)