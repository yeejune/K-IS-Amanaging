# 시스템 정보 수집 스크립트

# 자동 시작 항목
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" > Autostart_RunKey_HKCU_SOFTWARE_Microsoft_Windows_CurrentVersion_Run.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" > Autostart_RunKey_HKCU_SOFTWARE_Microsoft_Windows_CurrentVersion_RunOnce.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > Autostart_RunKey_HKLM_SOFTWARE_Microsoft_Windows_CurrentVersion_Run.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" > Autostart_RunKey_HKLM_SOFTWARE_Microsoft_Windows_CurrentVersion_RunOnce.txt

# 예약 작업
schtasks /query /fo LIST /v > Autostart_ScheduledTasks_SCHTASKS.txt

# 서비스 목록
sc query > Autostart_Services_SC.txt

# 이벤트 로그
wevtutil qe Application /c:100 /f:text > EventLog_Application_Recent.txt
wevtutil qe Security /c:100 /f:text > EventLog_Security_Recent.txt
wevtutil qe System /c:100 /f:text > EventLog_System_Recent.txt

# 네트워크 정보
ipconfig /all > Network_IPConfig_All.txt
netstat -an > Network_Netstat_an.txt

# 사용자 및 그룹
net user > Local_Users.txt
net localgroup > Local_Groups.txt

# 공유 폴더
net share > Shared_Folders.txt

# 시스템 정보
systeminfo > System_Info.txt
# 날짜 저장
Get-Date -Format "yyyy-MM-dd" | Out-File -Encoding UTF8 System_Date.txt

# 시간 저장
Get-Date -Format "HH:mm:ss" | Out-File -Encoding UTF8 System_Time.txt


# 프로세스 목록
tasklist /v > Processes_TaskList_V.txt
