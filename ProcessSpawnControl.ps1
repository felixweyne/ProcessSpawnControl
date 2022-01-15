########################################
#
# Process Spawn Control (PsC)
# 
# A powershell tool which aims to help in the behavioral (process) analysis of malware.
# Process Spawn Control suspends newly launched processes and gives the analyst the option 
# to either keep the process suspended or to resume it, allowing the process to run.
#
# WARNING: ONLY USE THIS IN A SANDBOX ENVIRONMENT, not on a production PC.
# Failure to follow this warning may lead to the creation of a black hole, 
# your PC crashing, or it might just create some slight anoyances by freezing 
# some user interface windows.
#
# Author: Felix Weyne, 2018
########################################

#Test samples (SHA1)
#Packed Azorult: fb339b3457568f02b176608e96005b102015edd7
#Emotet dropper: 2a526d67e19ec848afe76bfe8a9532fe96b51600

#Settings
$popupWidth=420; #Width of the GUI popup.
$popupScreenBorderDistance=20; 
$ignoredProcesses=@("dllhost.exe","SearchProtocolHost.exe","SearchFilterHost.exe","taskhost.exe","conhost.exe","backgroundTaskHost.exe","explorer.exe"); #these processes will never be suspended
$new_process_check_interval = New-Object System.TimeSpan(0,0,0,0,250); #public TimeSpan (int days, int hours, int minutes, int seconds, int milliseconds);
$suspend_parent_process=$false;

#
# 1. Functionality to suspend and resume processes
# Source of this function: Poshcode, Joel Bennett 
#
Add-Type -Name Threader -Namespace "" -Member @"
	[Flags]
	public enum ProcessAccess : uint
	{
		Terminate = 0x00000001,
		CreateThread = 0x00000002,
		VMOperation = 0x00000008,
		VMRead = 0x00000010,
		VMWrite = 0x00000020,
		DupHandle = 0x00000040,
		SetInformation = 0x00000200,
		QueryInformation = 0x00000400,
		SuspendResume = 0x00000800,
		Synchronize = 0x00100000,
		All = 0x001F0FFF
	}

	[DllImport("ntdll.dll", EntryPoint = "NtSuspendProcess", SetLastError = true)]
	public static extern uint SuspendProcess(IntPtr processHandle);

	[DllImport("ntdll.dll", EntryPoint = "NtResumeProcess", SetLastError = true)]
	public static extern uint ResumeProcess(IntPtr processHandle);

	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

	[DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool CloseHandle(IntPtr hObject);
"@

function Suspend-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to suspend process: $processID"

		$result = [Threader]::SuspendProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to suspend. SuspendProcess returned: $result"
			return $False
		}
		[Threader]::CloseHandle($pProc) | out-null;
	} else {
		Write-Error "Unable to open process. Not elevated? Process doesn't exist anymore?"
		return $False
	}
	return $True
}

function Resume-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to resume process: $processID"
		Write-Host ""
		$result = [Threader]::ResumeProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to resume. ResumeProcess returned: $result"
		}
		[Threader]::CloseHandle($pProc) | out-null
	} else {
		Write-Error "Unable to open process. Process doesn't exist anymore?"
	}
}

#
# 2. Functionality to create user interface popup dialog
#
function GenerateForm($processName,$processID,$parentOrChildProcessName,$isSuspendedParentProcess) {
	[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null;
	[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null;

	$screen = [System.Windows.Forms.Screen]::PrimaryScreen;
	$bounds = $screen.Bounds;
	 
	$mainForm = New-Object System.Windows.Forms.Form;
	$labelProcessRun = New-Object System.Windows.Forms.Label;
	$labelRunningProcess = New-Object System.Windows.Forms.Label;
	$labelProcessID = New-Object System.Windows.Forms.Label;
	$labelParentProcessID = New-Object System.Windows.Forms.Label;
	$closeFormButton = New-Object System.Windows.Forms.Button;
	$resumeButton = New-Object System.Windows.Forms.Button;
	$suspendButton = New-Object System.Windows.Forms.Button;

	#button event handlers;
	$handler_closeFormButton_Click={
		$this.findform().close();
	}

	$handler_resumeButton_Click={ 
		[int]$processToResume=[convert]::ToInt32($this.Tag);
		Resume-Process -processID $processToResume
		$this.findform().close();

	}
	$handler_suspendButton_Click={
		$this.findform().close();
	}

	#resume/suspend form
	$popupHeight=$popupWidth*0.4;
	$mainForm.Size = new-object System.Drawing.Size $popupWidth,$popupHeight;
	$mainForm.ControlBox = $False;
	$mainForm.Name = "mainForm";
	$mainForm.FormBorderStyle = 'None';
	$mainForm.BackColor = '#2c3e5b';
	$mainForm.Text = "New process";
	$mainForm.Left = $bounds.Right-$popupWidth-$popupScreenBorderDistance; 
	$mainForm.Top = $bounds.Top+$popupScreenBorderDistance	; 
	$mainForm.StartPosition = 'Manual'; 

	#label description new process
	$labelProcessRun.Text = "The following process wants to run:"
	$labelProcessRun.AutoSize = $True
	$labelProcessRun.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelProcessRun.ForeColor = 'white';
	$labelProcessRun_drawingPoint = New-Object System.Drawing.Point;
	$labelProcessRun_drawingPoint.X = ($popupWidth*0.05);
	$labelProcessRun_drawingPoint.Y = ($popupHeight*0.06);
	$labelProcessRun.Location = $labelProcessRun_drawingPoint;

	#label running process
	$labelRunningProcess.Text = "Process: $processName"
	$labelRunningProcess.AutoSize = $True
	$labelRunningProcess.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelRunningProcess.ForeColor = 'white';
	$labelRunningProcess_drawingPoint = New-Object System.Drawing.Point;
	$labelRunningProcess_drawingPoint.X = ($popupWidth*0.05);
	$labelRunningProcess_drawingPoint.Y = ($popupHeight*0.25);
	$labelRunningProcess.Location = $labelRunningProcess_drawingPoint;

	#label process id
	$labelProcessID.Text = "Process ID: $processID"
	$labelProcessID.AutoSize = $True
	$labelProcessID.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelProcessID.ForeColor = 'white';
	$labelProcessID_drawingPoint = New-Object System.Drawing.Point;
	$labelProcessID_drawingPoint.X = ($popupWidth*0.05);
	$labelProcessID_drawingPoint.Y = ($popupHeight*0.4);
	$labelProcessID.Location = $labelProcessID_drawingPoint;

	#label parent process name 
	$labelParentProcessID.Text = "Parent Process: $parentOrChildProcessName"
	if ($isSuspendedParentProcess){
		$labelParentProcessID.Text = "Child Process: $parentOrChildProcessName"
	}
	$labelParentProcessID.AutoSize = $True
	$labelParentProcessID.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelParentProcessID.ForeColor = 'white';
	$labelParentProcessID_drawingPoint = New-Object System.Drawing.Point;
	$labelParentProcessID_drawingPoint.X = ($popupWidth*0.05);
	$labelParentProcessID_drawingPoint.Y = ($popupHeight*0.55);
	$labelParentProcessID.Location = $labelParentProcessID_drawingPoint;

	#CloseForm Button
	$closeFormButton.TabIndex = 2;
	$closeFormButton_drawingSize = New-Object System.Drawing.Size;
	$closeFormButton_drawingSize.Width = 0.05*$popupWidth;
	$closeFormButton_drawingSize.Height = 0.05*$popupWidth;
	$closeFormButton.Size = $closeFormButton_drawingSize;
	$closeFormButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat;
	$closeFormButton.FlatAppearance.BorderSize = 0;
	$closeFormButton.ForeColor = 'White';
	$closeFormButton.Text = "X";

	$closeFormButton_drawingPoint = New-Object System.Drawing.Point;
	$closeFormButton_drawingPoint.X = ($popupWidth*0.93);
	$closeFormButton_drawingPoint.Y = ($popupHeight*0.05);
	$closeFormButton.Location = $closeFormButton_drawingPoint;

	#resume process button
	$resumeButton.TabIndex = 0;
	$resumeButton_drawingSize = New-Object System.Drawing.Size;
	$resumeButton_drawingSize.Width = 0.40*$popupWidth;
	$resumeButton_drawingSize.Height = 0.20*$resumeButton_drawingSize.Width;
	$resumeButton.Size = $resumeButton_drawingSize;
	$resumeButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat;
	$resumeButton.FlatAppearance.BorderColor = 'White';
	$resumeButton.ForeColor = 'White';
	$resumeButton.BackColor = '#169355';
	$resumeButton.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$resumeButton.Text = "Allow run";
	$resumeButton.Tag = $processID;

	$resumeButton_drawingPoint = New-Object System.Drawing.Point;
	$resumeButton_drawingPoint.X = ($popupWidth*0.05);
	$resumeButton_drawingPoint.Y = ($popupHeight*0.75);
	$resumeButton.Location = $resumeButton_drawingPoint;

	#suspend process button
	$suspendButton.TabIndex = 1;
	$suspendButton_drawingSize = New-Object System.Drawing.Size;
	$suspendButton_drawingSize.Width = $resumeButton_drawingSize.Width;
	$suspendButton_drawingSize.Height = $resumeButton_drawingSize.Height;
	$suspendButton.Size = $suspendButton_drawingSize;
	$suspendButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat;
	$suspendButton.FlatAppearance.BorderColor = 'White';
	$suspendButton.ForeColor = 'White';
	$suspendButton.BackColor = '#921650';
	$suspendButton.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$suspendButton.Text = "Keep suspended";

	$suspendButton_drawingPoint = New-Object System.Drawing.Point;
	$suspendButton_drawingPoint.X = $popupWidth-($popupWidth*0.05) - $resumeButton_drawingSize.Width;
	$suspendButton_drawingPoint.Y = $resumeButton_drawingPoint.Y;
	$suspendButton.Location = $suspendButton_drawingPoint;

	#add event handlers to buttons
	$closeFormButton.add_Click($handler_closeFormButton_Click);
	$resumeButton.add_Click($handler_resumeButton_Click);
	$suspendButton.add_Click($handler_suspendButton_Click);

	#add controls to form
	$mainForm.Controls.Add($closeFormButton);
	$mainForm.Controls.Add($resumeButton);
	$mainForm.Controls.Add($suspendButton);
	$mainForm.Controls.Add($labelProcessRun);
	$mainForm.Controls.Add($labelProcessID);
	$mainForm.Controls.Add($labelParentProcessID);
	$mainForm.Controls.Add($labelRunningProcess);

	#If we call $mainForm.ShowDialog() to launch the form, the console and form will share the same thread.
	#This means that the form will launch, and no further code of the powershell script will be processed run until the form closes.
	#We need to work around this by launching the form in a new runspace.
	#Source of tis code snippet: LogicVomit, Reddit. https://www.reddit.com/r/PowerShell/comments/41lebp/how_to_close_a_runspace_from_a_powershell_gui/ 
	$Runspace = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($Host);
	$Runspace.ApartmentState = 'STA';
	$Runspace.ThreadOptions = 'ReuseThread';
	$Runspace.Open();

	$Runspace.SessionStateProxy.SetVariable('mainForm', $mainForm);

	#Create new thread
	$PowerShellRunspace = [System.Management.Automation.PowerShell]::Create();
	$PowerShellRunspace.Runspace = $Runspace;
	$PowerShellRunspace.AddScript({
		$mainForm.ShowDialog();
	}) | out-null;

	# open and run the runspace asynchronously
	$AsyncResult = $PowerShellRunspace.BeginInvoke();
}

#
# 3. Functionality to monitor newly created processes & interact with the suspend/resume functionality.
# 	 This makes use of Windows Management Instrumentation to get information about newly created processes.
#

#There is a bug in WqlEventQuery which occurs when the supplied time interval is too small and if your system locale is non-English (e.g. Belgian).
#(relevant StackOverflow page: https://stackoverflow.com/questions/5953434/wmi-query-in-c-sharp-does-not-work-on-non-english-machine)
#Should you get the error "Exception calling WaitForNextEvent ... Unparsable query", uncomment the below code which changes the culture for the PS session.
$culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US');
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture;
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture;

Write-Host "Monitoring newly spawned processes via WMI...";
Write-host "";

#https://docs.microsoft.com/en-us/dotnet/api/system.management.wqleventquery.withininterval
$scope = New-Object System.Management.ManagementScope("\\.\root\cimV2");
$query = New-Object System.Management.WQLEventQuery("__InstanceCreationEvent",$new_process_check_interval,"TargetInstance ISA 'Win32_Process'" );
$watcher = New-Object System.Management.ManagementEventWatcher($scope,$query);

$processSpawnCounter=1;
do
{
	$newlyArrivedEvent = $watcher.WaitForNextEvent(); #Synchronous call! If Control+C is pressed to stop the PowerShell script, PS will only react once the call has returned an event.
	$e = $newlyArrivedEvent.TargetInstance;
	Write-Host "($processSpawnCounter) New process spawned:";

	$processName=[string]$e.Name;
	Write-host "PID:`t`t" $e.ProcessId;
	Write-host "Name:`t`t" $processName;
	Write-host "PPID:`t`t" $e.ParentProcessID; 
	
	$parent_process=''; 
	try {$proc=(Get-Process -id $e.ParentProcessID -ea stop); $parent_process=$proc.ProcessName;} catch {$parent_process='unknown';}
	Write-host "Parent name:`t" $parent_process; 
	Write-host "CommandLine:`t" $e.CommandLine;

	if (-not ($ignoredProcesses -match $processName))
	{
		if(Suspend-Process -processID $e.ProcessId){
			Write-Host "Process is suspended. Creating GUI popup.";
			if($suspend_parent_process -And ($parent_process -ne "unknown")){
				$parent_process=$parent_process+".exe";
				if(-not ($ignoredProcesses -match $parent_process)){
					write-host ">>Suspending parent of "$processName" : "$parent_process
					if(Suspend-Process -processID $e.ParentProcessID){
						Write-Host ">>Suspended parent process. Creating GUI popup.";
						GenerateForm -processName $parent_process -processID $e.ParentProcessID -parentOrChildProcessName $processName -isSuspendedParentProcess $true;
					}
				}else{
					Write-Host "Would have suspended parent process: "$parent_process". But process is present in ignorelist.";
				}
			}
			GenerateForm -processName $processName -processID $e.ProcessId -parentOrChildProcessName $parent_process -isSuspendedParentProcess $false;
		}
	}else{
		Write-Host "Process ignored as per configuration.";
	}

	Write-host "";
	$processSpawnCounter += 1;
} while ($true)