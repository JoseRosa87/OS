# OS
For OS Section


Day 1 Powershell        https://os.cybbh.io/public/os/latest/002_powershell/pwsh_fg.html
__________________

To get-host | select-object Version (This gets the powershell version)  Or user the PS versions. 

To switch versions: PS C:\> get-host | select-object Version 
To exit back to previouse section, type <exit>
To find help <get-help> 
list available properties or methods <get-member>    get-process | get-memeber 

+++     (cmdlet).property                              # Command Structure
++++    (Get-Process).Name                             # Returns the single property of 'name' of every process
++++   (Get-Process notepad).Kill()


Start-Process calc                              # Open an instance of calculator
++++    (Get-Process calculator*).kill()                # Stops a named process using the kill() method directly
Stop-Process -name calculator*                  # Uses a cmdlet to call the Process.Kill method



    PowerShell allows for the properties and methods to be called within a pipe by using $_.(The Pipelined Variable)

        The variable will always be of the same type as the object coming from the previous command.


Get-Process | Select-Object Name, ID, path | Where-object {$_.ID -lt '1000'}            # List all the processes with a PID lower than 1000
(Get-Process | Select-Object Name, ID, path | Where-object {$_.ID -lt '1000'}).count    # List all the processes with a PID lower than 1000

Pipelining

    Objects in Powershell are passed along in pipes (|) based off their inputted cmdlets

Get-LocalUser | Get-Member      # Displays Properties and Methods of Get-LocalUser cmdlet


You will be using CIM instead of WMI. WMI is depricated. Gives you more details such as the parant process ID. 

Get-Cimclass *                                                                  # Lists all CIM Classes
Get-CimInstance –Namespace root\securitycenter2 –ClassName antispywareproduct   # Lists the antispywareproduct class from the root/security instance
Get-CimInstance -ClassName Win32_LogicalDisk -Filter “DriveType=3” | gm         # Shows properties and methods for this Instance
Get-WmiObject -Class Win32_LogicalDisk -Filter “DriveType=3”                    # Using the Windows Management Instrumentation method

_________________________________________________________________________________________________________________________________________________________
2.1.1 Do Loop (NOT ON THE TEST) 

    The Do statement runs a statement list one or more times, subject to a While or Until condition.

        The Do keyword works with the While keyword or the Until keyword to run the statements in a script block, subject to a condition.

            A Do-While Loop is a variety of the While loop. In a Do-While Loop, the condition is evaluated after the script block has run. As in a While loop, the script block is repeated as long as the condition evaluates to true.

            Like a Do-While Loop, a Do-Until Loop always runs at least once before the condition is evaluated. However, the script block runs only while the condition is false.


Do-until (runs once until the condition if false)
Do-while (runes until the condition is true) 
do {<statement list>} while (<condition>)
do {<statement list>} until (<condition>)


2.1.2 For Loop   (++ INCREMENT -- DECREMENT)

    The For statement (also known as a For Loop) is a language construct you can use to create a loop that runs commands in a command block while a specified condition evaluates to $true.

        A typical use of the For Loop is to iterate an array of values and to operate on a subset of these values.

            In most cases, if you want to iterate all the values in an array, consider using a Foreach statement.


For statement syntax

for (<Init>; <Condition>; <Repeat>)
{
    <Statement list>
}


____________________________________________________________________________________________________________
2.1.3 Foreach Loop

    The Foreach statement (also known as a Foreach Loop) is a language construct for stepping through (iterating) a series of values in a collection of items.

        The simplest and most typical type of collection to traverse is an array.

            Within a Foreach Loop, it is common to run one or more commands against each item in an array.


Displays the values in the $letterArray array

$letterArray = "a","b","c","d"
foreach ($letter in $letterArray)
{
  Write-Host $letter
}

Iterates through the list of items that is returned by the Get-ChildItem cmdlet

foreach ($file in Get-ChildItem)
{
  Write-Host $file
}


Displays the numbers 1 through 3 if the $val variable has not been created or if the $val variable has been created and initialized to 0

while($val -ne 3)
{
    $val++
    Write-Host $val
}
#or
while($val -ne 3){$val++; Write-Host $val}

____________________________________________________________________________
To view erros use $error | select -first 1



 PowerShell Conditions

    PowerShell structures can have one or more conditions to be evaluated or tested by the script, along with a statement or statements that are to be executed if the condition is determined to be true, and optionally, other statements to be executed if the condition is determined to be false.

        In other words, run statement lists based on the results of one or more conditional tests.

If statement syntax

if (<test1>)
    {<statement list 1>}
[elseif (<test2>)
    {<statement list 2>}]
[else
    {<statement list 3>}]

if (1 -gt 2) {write-host "1 is greater than 2"} else {Write-Host "Nope!"}




2.3 PowerShell Variables

    PowerShell uses Variables as a unit of memory to store all types of values.

        It can store the results of commands, and store elements that are used in commands and expressions, such as names, paths, settings, and values.

            Variables are represented by text strings that begin with a dollar sign $, such as $a, $process, or $my_var.


2.3.1 User-Defined Variables

    Variables created and maintained by the User.

        By default these exist only in the PowerShell windows that you have open. When they close they are lost.

        To save a variable, add it to your PowerShell profile.

	You can store any type of object in a variable, including integers, strings, arrays, and hash tables. And, objects that represent processes, services, event logs, and computers.
Retrieve list of current Variables

Get-Variable                      # Names are displayed without the preceding <$>
Clear-Variable -Name MyVariable   # Delete the value of a Variable
Remove-Variable -Name MyVariable  # Delete the Variable

Creating a Variable

$MyVariable = 1, 2, 3             # Creates the MyVariable with 1,2,3

Creating a Variable of command results

$Processes = Get-Process          # Creates a Variable with the results of Get-Process
$Today = (Get-Date).DateTime      # Creates a combined Date/Time variable from the results of Get-Date

    The data type of a variable is determined by the .NET types of the values of the variable. To view a variable’s object type, use Get-Member.

How to find the data type

$PSHome | Get-Member              # Displays System.String with it's objects and properties
$A=12                             # Creating A with an integer
$A | Get-Member                   # Displays System.Int32





Creating an Array

$A = 22,5,10,8,12,9,80

Calling the Array

C:\PS> Echo $A
22
5
10
8
12
9
80

Creating an Array with '..'

$A[1..4]
C:\PS> Echo $A
1
2
3
4

ForEach loop to display the elements in the $A array

$A = 0..9
foreach ($element in $A) {
  $element
}
#output
0
1
2
3
4
5
6
7
8
9

For loop to return every other value in an array

$A = 0..9
for ($i = 0; $i -le ($a.length - 1); $i += 2) {
  $A[$i]
}
#output
0
2
4
6
8

While loop to display the elements in an array until a defined condition is no longer true

$A = 0..9
$i=0
while($i -lt 4) {
  $A[$i];
  $i++
}
#output
0
1
2
3


2.5 PowerShell Functions

    Functions allows quick running custom code rather than having to string multiple commands together every time you need them.

Get-Help about_Functions                                      # Displays the help about Functions
Get-Help about_Functions_Advanced                             # Displays some more in-depth help about Functions
Function Do-Stuff { Get-Date; Get-Process; Get-Service }      # Creates a Function with 'Get-Date, Get-Process, Get-Service' inside of it
Do-Stuff                                                      # Runs the Function


	Functions are essentially a list of commands that serve a specific purpose.


2.6 PowerShell Execution Policy

    Powershell uses .ps1 files as a way to run a series of PowerShell commands, with each command appearing on a separate line to make up a script.

        By default policy is Restricted. This disallows all scripts not created in the local intranet zone aka the local machine or within a workgroup.

            As a security concern, scripts can contain a host of malicious information and should require specific permissions and validation prior to execution.

Get-ExecutionPolicy -list                                             # Lists all of the Scopes and ExecutionPolicies on the system
Get-ExecutionPolicy                                                   # Gets the current user's ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser  # Sets the ExecutionPolicy for the CurrentUser to Unrestricted


2.7 PowerShell Comparison Operators

    In PowerShell Comparison Operators let you compare values or finding values that match specified patterns.

        In other words they also allow you to either compare two values or filter elements of a collection against an input value.

    They can do the following:
    	Equality
    	Matching
    	Replacement
    	Containment
    	Type

Help and Comparison command format

get-help about_comparison_operators
Get-Service | Where-Object {$_.Status -eq "Stopped"}            # Takes the output from Get-Service and looks for Status property of Stopped and list those Services
Get-Service | where Status -eq "Stopped"                        # Same as above
Get-Process | Where-Object -Property Handles -GE -Value 1000    # Lists Processes that have Greater Than 1000 Handles
Get-Process | where Handles -GE 1000                            # Same as above

	Where alias is substituted for the Where-Object


2.8 Commenting in PowerShell

    In PowerShell single line comments start with a hash symbol, everything to the right of the # will be ignored.

        In PowerShell 2.0 and above multi-line block comments can be used.

            Multi-line comments are typically used to add descriptive help at the start of a script, but also work to embed comment text within a command.

Get-Process # comment                                           # Creates a comment beside cmdlet
<# comment                                                      # Begins a multiline comment
|
|
comment #>                                                      # Ends the multiline comment



3. PowerShell Profiles

    PowerShell profiles are a convenient way to store PowerShell configuration information as well as personalized aliases and functions to persistent use in every PowerShell session.

	Profiles are just scripts that have configurations set.

    PowerShell profiles were intended to assist PowerShell users with mundane repeatable tasks, such as loading PowerShell module daily, or configuring.

        By default the profiles are not built, the paths are checked whenever PowerShell is opened.

$Profile

    PowerShell supports several profile files and host programs, like Windows, support their own specific profiles. The profiles below are listed in order of precedence with the first profile having the highest precedence.

Description 	Path

All Users, All Hosts
	

$PsHome\Profile.ps1

All Users, Current Host
	

$PsHome\Microsoft.PowerShell_profile.ps1

Current User, All Hosts
	

$Home\[My]Documents\Profile.ps1

Current User, Current Host
	

$Home\[My ]Documents\WindowsPowerShell\Profile.ps1


In addition, other programs that host PowerShell can support their own profiles. For example, PowerShell Integrated Scripting Environment (ISE) supports the following host-specific profiles.
Description 	Path

All users, Current Host
	

$PsHome\Microsoft.PowerShellISE_profile.ps1

Current user, Current Host
	

$Home\[My]Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1


3.1 PowerShell Profile Paths

    The profile paths include the following variables:

$PsHome         # Stores the installation directory for PowerShell
$Home           # Stores the current user’s home directory

THE $PROFILE VARIABLE

    The $Profile automatic variable stores the paths to the PowerShell profiles that are available in the current session.

    To view a profile path, display the value of the $Profile variable. You can also use the $Profile variable in a command to represent a path.

    The $Profile variable stores the path to the "Current User, Current Host" profile. The other profiles are saved in note properties of the $Profile variable.

    For example, the $Profile variable has the following values in the Windows PowerShell console.

$profile | Get-Member -Type NoteProperty                        # Displays the profile values of Names, MemberType, and Paths.
$Profile | get-member -type noteproperty | ft -wrap             # Displays the same results but completed in case it was cut off '...'
$PROFILE | Get-Member -MemberType noteproperty | select name    # Narrowed results to display only Names

    To determines whether individual profiles have been created on the local computer:

Test-Path -Path $profile.currentUsercurrentHost
Test-Path -Path $profile.currentUserAllHosts
Test-Path -Path $profile.AllUsersAllHosts
Test-Path -Path $profile.AllUserscurrentHost

3.2 Creating A PowerShell Profile

    We can also create profiles for the current user in the current PowerShell host application.

New-Item -ItemType File -Path $profile -Force                 # Creates a $Profile for the CurrentUser. Force is used to ignore any errors.
ISE $profile                                                  # Opens your newly created $Profile, which is empty

    By default, PowerShell Aliases are not saved if you close a PowerShell window session.

        For example, if you create a few Aliases and close the PowerShell window, you will be required to recreate the same PowerShell aliases.

            This would obviously present a problem if you have Aliases set up for use in PowerShell scripts.

New-Alias -Name DemUsers -Value Get-LocalUser

Building Functions in your PowerShell Profile
	Beyond the scope of the class but good knowledge

function Color-Console {
  $Host.ui.rawui.backgroundcolor = "black"
  $Host.ui.rawui.foregroundcolor = "green"
  $hosttime = (Get-ChildItem -Path $PSHOME\PowerShell.exe).CreationTime
  $hostversion="$($Host.Version.Major)`.$($Host.Version.Minor)"
  $Host.UI.RawUI.WindowTitle = "PowerShell $hostversion ($hosttime)"
  Clear-Host
}
Color-Console

Transcript

    We can turn on PowerShell transcripts to keep track of commands that have been run.

	Currently the only downfall of transcript is that it does not work with ISE.

start-transcript
start-transcript | out-null                       # Pipe to out-null so users don't see that commands are being recorded

Start-Transcript C:\MyWork.txt                    # Starts to log commands into the c:\mywork.txt file
Get-Service                                       # Run get-service command and inputs that and the results into the transcript.
Stop-Transcript                                   # End the transcript
notepad c:\MyWork.txt                             # View the contents of the created transcript



4. Windows Remoting

    PowerShell remoting is the next evolution in windows remote management.

        Instead of relying on Distributed Component Object Model (DCOM), it uses the Window Remote Management Protocol (WinRM) and Web Services Management (WS-Man) to manage these communications.

            Using these two protocols allows for a simplified network configuration.

                It does in two ways: only one port is needed to be opened through the firewall and WinRM’s communication is encrypted.

	PowerShell remoting has been available since PowerShell Version 2.


	When the sessions have 2 different versions of PowerShell, the session will default to the lower version. This can limit the cmdlets you have available.


    By default, the user initiating the remote connection must be in an administrators group or remote management group.

        This can be changed using the session parameters for WinRM.

Get-PSSessionConfiguration                        # Displays permissions


    PowerShell Remoting has to be enabled on client workstations, but it is on by default in Windows Server 2012 and newer.

        On a client version of Windows that has a public network profile enabled, you will need to use the -SkipNetworkProfileCheck parameter or Enable-PSRemoting will fail.

            This will add a firewall rule for public networks that allows remote connections only from hosts in the same local subnet.

Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'   # Queries current network profiles.

Table 1. Network Profile Registry Values Network Location Category 	Data Value

Public
	

0 (ZERO)

Private
	

1

Domain
	

2


4.1 PowerShell Remoting Security

    WinRM uses Kerberos for authentication by default.

        It also encrypts all communications with a per-session AES-256 symmetric key.

        Uses ports 5985 for HTTP by default or 5986 for HTTPS. HTTPS requires extra set-up for SSL certificates.

	WinRM is already encrypted, but HTTPS will encrypt the packet headers as well.

    Although, New-PSSession, Enter-PSSession, and Invoke-Command accepts an IP address as a value, Kerberos does not and NTLM authentication will be used.

winrm get winrm/config          # Displays the WinRM configuration


    If you are outside of a Active Directory Domain then you have two options: HTTPS or adding the host to the Trusted Hosts file.

        Trusted Hosts can be used in a workgroup environment or inter-domain.

	Understand any host that you are putting in this list you are trusting 100%.

From Don Jones:
“And be aware that setting TrustedHosts to * is a good override of every security protection Microsoft provides. It’s easy, but it does make it very easy for an attacker to spoof connections, grab your credentials, and do awful stuff. If you’re just using * to test, okay, but be aware that it’s not a very safe configuration.”

    The trusted hosts is set by the last set-item command ran.

        Add more hosts by putting the current values in a variable and include the additional hosts you want to add.

            You can only completely overwrite or append content to the string value in Trusted Hosts.

Get-Item WSMan:\localhost\client\TrustedHosts                                      # Query trusted hosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Server01"                    # Adding a single item to TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Server01,Server02,127.0.0.1"      # Adding multiple items
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "Server03" -Concatenate       # Appends the Value instead of changing it

    When you use -ComputerName for a cmdlet in PowerShell, it is running the command on the local host to query the information on the remote host.

    Get-WMIObject DCOM (Distributed Component Object Model) for remote WMI (Windows Management Instrumentation) connections.



5. Remoting commands

    PSRemoting consists of two separate concepts: Temporary and Persistent Sessions.

        Invoke-Command can be used to automate command execution across a domain using both temporary and new-sessions.

5.1 Temporary Sessions

    Invoke-Command is not a remoting command. It is how everything is done in PowerShell.

        If you are querying a large number of hosts and/or data you can use the -asjob parameter to run it in the background.

Invoke-Command -ComputerName File-Server {Get-Service}                                      # Creates 1-to-1 Temporary Session
Invoke-Command -ComputerName File-Server,Domain-Controll,Workstation2 {Get-Service} -asjob  # Running a Temporary Session as a Job
Receive-Job <job #>                                                                         # Displays the job's Results



6. .NET API Framework

    An API stands for application programming interface. It is a library of functions designed to simplify interaction between and client and a server.

        CMDLETs natively use them to perform their functions. However, there is not a CMDLET for every potential use of Powershell. The native .NET API functions fill this capability gap.


6.1 Locating .NET API Functions
NET APIs are broken into namespaces. They are located at the link below:

Microsoft .NET API Browser


6.2 Using a Namespace

A namespace is always invoked by using [NameSpace.Class]::Method()
The example below uses the Encoding and Decoding functionality of the System.Text Namespace to Encode or Decode strings of text into various forms.

Invoking the System.Text Namespace, Encoding Class, and GetBytes

[System.Text.Encoding]::GetBytes()

	Use Powershell ISE it has syntax highlighting and can list Classes and Methods Automatically


6.3 Functional Usage of .NET APIs

Converts the text into a Unicode Array

([System.Text.Encoding]::Unicode.GetBytes("This Might be important")) 

	Convert the text This might be important into Unicode


Download a File with Powershell

$url = "http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_win64_standalone.zip"
$output = "$PSScriptRoot\volatility_2.6_win64_standalone.zip"
$start_time = Get-Date

$wc = New-Object System.Net.WebClient 
$wc.DownloadFile($url, $output) 


(New-Object System.Net.WebClient).DownloadFile($url, $output)


