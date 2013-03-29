for %%i in (C:\Malwares\*) do (
md logs
C:\pin\pin -t C:\GitHub\CP4101\ParanoidDetector\Debug\PinTool.dll -- %%i
ren C:\GitHub\CP4101\logs %%~ni
)