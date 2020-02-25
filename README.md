# win_audit
Basic Windows Server Auditing Script

<br>

Instructions for running PowerShell script on a Windows target:

1. Be sure you are authenticated to the target servers as either Local Administrator or as Domain Administrator.
2. Copy <code>win_audit.ps1</code> to a location on your target server.
3. Open a PowerShell session as Administrator: <pre>[Cmd+r] + "PowerShell" + [Ctrl+Shift+Enter]</pre>
4. <pre>cd Desktop </pre>
5. <pre>SetExecutionPolicy Unrestricted</pre>
   If you get the error: <pre>SetExecutionPolicy: The term 'SetExecutionPolicy' is not recognized as the name of a cmdlet, [...]</pre>
   Make sure you are logged in as the Local Admin or Domain Admin.
   If you get the above error again, skip this step.
6. Run the script by entering: <pre>.\win_audit.ps1</pre>
   As the script runs, you will occasionally see error messages in red font scroll up the PowerShell console. This in normal and can be ignored. The script is checking for specific registry entries.
7. The script will take from 5 mins to 20 mins to complete; an output file will be created whose name starts with the computer's name. For example: COMPNAME-CONFIG_DUMP_20190249_02321PM.txt
8. Delete <code>win_audit.ps1</code> from the target server.
