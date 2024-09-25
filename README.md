# passwordFilter
A malicious password filter for competition defence techniques @ RIT.


# USAGE
1. Compile the dll with a custom path, or use the provided sample
2. Edit the regkey HKLM:\System\CurrentControlSet\Control\Lsa -> notificationPackages
   - ADD (do not remove the existing items) the name of your dll on a new line. Do NOT include the extension
   - For the sample dll this would be "libfilter"
3. restart the machine
4. in process explorer you should be able to see the DLL loaded under lsass.exe (select lowerpane > dlls, you must be running as admin)
5. passwords should be saved in C:\Windows\temp\lsass.log
