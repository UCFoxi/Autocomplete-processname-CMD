# Autocomplete-processname-CMD
 Autocomplete process name with TAB in CMD

# How 2 use
1. Copy 'CmdProcessNameAutoComplete.dll' into 'C:\Windows\System32\' folder!
2. Start 'AutoLoadDllToCmd.exe' as Admin!

Optional:
Add 'AutoLoadDllToCmd.exe' to autostarts:
1. open 'taskschd.msc'
2. click 'Action' -> 'Import Task...'
3. select 'AutoLoadDllToCmd.xml'
4. in the popup window goto 'Actions' and change the 'AutoLoadDllToCmd.exe' filepath to your own one!
5. press 'OK'
6. in the popup window goto 'General' and enable 'Run with highest pivileges'.
6. press 'OK'
7. select 'AutoLoadDllToCmd' and click 'Run' once!
* You will see 'AutoLoadDllToCmd.exe' is running in background!