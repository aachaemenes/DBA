# Encrypt and save password - Run this once manually
#$Password = "APS SA PASSWORD" | ConvertTo-SecureString -AsPlainText -Force
#$EncryptedPassword = $Password | ConvertFrom-SecureString
#$EncryptedPassword | Set-Content "C:\Scripts\encryptedPassword.txt"

# Configuration and Connection Details
$server = "10.95.0.26,17001"
#$server="GLDDS85455"i
# Flag for Windows Authentication
$useWindowsAuthentication = $false  # Change to $true if you want to use Windows Authentication

$LoginNamePattern = '%becky%edwards%'  # Replace '%pattern%' with your desired login name pattern
$ReportFlag = $false  # Set to $true to generate a report, $false otherwise


# Flags and Variables
# Create Login
$createNewLoginFlag = $true  # Set to $true to create a new login
$LoginName = 'becky.edwards'  # New login username
$newLoginPassword = 'Temp123'  # New login password

# Reset Password
$resetPasswordFlag = $false  # Set to $true to reset password
$resetPassword = ''  # New password for the login

# Unlock Account
$unlockAccountFlag = $false  # Set to $true to unlock the account

# Disable Login
$disableLoginFlag = $false  # Set to $true to disable the login

# Enable Login
$enableLoginFlag = $false  # Set to $true to enable the login

# Delete Login
$deleteLoginFlag = $true  # Set to $true to delete the login

# Create Service Account
$createServiceAccountFlag = $false  # Set to $true to create a service account
$serviceLogin = ''  # Service account username
$requesterEmail = ''  # Email address of the requester
$date = Get-Date  # Date for the service account creation


# Database Permissions
$databaseAccessList = @('ES_CONTROLS_AXPROD_Staging','OARPTS_STAGING')  # List of databases to grant permissions. Use dbanames or all 
$dbRoleNames = @()  # Database role names like db_datareader, db_datawriter, db_dbowner

# Schema Permissions
$schemaAccessList = @('NONSEN')  # List of schemas to grant permissions
$schemaPermissionList = @('SELECT')  # List of permissions for schemas

# Object Permissions
$objectAccessList = @()  # List of objects to grant permissions
$permissionObjectAccessList = @()  # List of permissions for objects

# Email Configuration 
$sendEmailFlag = $true  # Set to $true to send email notification
$fromAddress = "sqldbateam.ess@baesystems.com"
$toAddress = "allen.heydari@baesystems.com"
$ccAddress="allen.heydari@baesystems.com"
$smtpServer = "smtp.goldlnk.rootlnka.net"
$emailSubjectNewAccount = "New SQL Server Account Created"
$emailSubjectUnlockReset = "SQL Server Account Unlocked and Reset"

# Import required module and set configuration
Import-Module dbatools
Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true
Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $false

$credential = $null
if (-not $useWindowsAuthentication) {
    # Use SQL Server Authentication with encrypted password
    $path = "C:\Scripts\encryptedPassword.txt"
    if (Test-Path $path) {
        $EncryptedPassword = Get-Content $path | ConvertTo-SecureString
        $credential = New-Object System.Management.Automation.PSCredential ('sa', $EncryptedPassword)
    } else {
        Write-Error "Encrypted password file not found. Please ensure the path is correct."
        return
    }
}


# Define the function for executing a query
function Execute-Query {
    param($Server, $Credential, $Database, $Query)
    Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Database $Database -Query $Query
}

# Define the function for generating a report
function Generate-Report {
    param($Server, $Credential, $LoginNamePattern, $ReportFlag)
    if ($ReportFlag) {
        $searchLoginQuery = "SELECT name FROM sys.server_principals WHERE name LIKE '$LoginNamePattern';"
        $existingLogins = Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Database 'master' -Query $searchLoginQuery

if ($existingLogins.Count -ne 0) {
    Write-Output "Matching logins in master database:"
    foreach ($login in $existingLogins) {
        Write-Output $login.name
    }
} else {
    Write-Output "No logins matching pattern '$LoginNamePattern' exist in master."
}

        # Proceed to check for users in all databases
        $databases = Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Query "SELECT name FROM sys.databases WHERE state = 0 AND name NOT IN ('master', 'tempdb', 'model', 'msdb')" | ForEach-Object { $_.name }

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, [math]::Min($databases.Count, [Environment]::ProcessorCount * 2))
        $runspacePool.Open()

        $runspaces = @()

        foreach ($db in $databases) {
            $runspace = [powershell]::Create().AddScript({
                param($Server, $Credential, $db, $LoginNamePattern)

                $query = @"
SELECT db_name() AS DBName,
       CASE princ.type
           WHEN 'S' THEN 'SQL User'
           WHEN 'U' THEN 'Windows User'
           WHEN 'G' THEN 'Windows Group'
       END AS UserType,
       princ.name AS UserName,
       ISNULL(USER_NAME(dbrole.role_principal_id), '') AS DatabaseRole,
       perm.permission_name,
       perm.state_desc AS PermissionState,
       CASE perm.class
           WHEN 1 THEN obj.type_desc
           ELSE perm.class_desc
       END AS ObjectType,
       objschem.name AS SchemaName,
       CASE perm.class
           WHEN 3 THEN permschem.name
           ELSE OBJECT_NAME(perm.major_id)
       END AS ObjectName,
       col.name AS ColumnName
FROM sys.database_principals AS princ
LEFT JOIN sys.server_principals AS ulogin ON ulogin.sid = princ.sid
LEFT JOIN sys.database_permissions AS perm ON perm.grantee_principal_id = princ.principal_id
LEFT JOIN sys.schemas AS permschem ON permschem.schema_id = perm.major_id
LEFT JOIN sys.objects AS obj ON obj.object_id = perm.major_id
LEFT JOIN sys.schemas AS objschem ON objschem.schema_id = obj.schema_id
LEFT JOIN sys.database_role_members AS dbrole ON princ.principal_id = dbrole.member_principal_id
LEFT JOIN sys.columns AS col ON col.object_id = perm.major_id AND col.column_id = perm.minor_id
WHERE princ.type IN ('S','U','G') AND (princ.name LIKE '$LoginNamePattern' OR ulogin.name LIKE '$LoginNamePattern')
"@
                Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Database $db -Query $query
            }).AddArgument($Server).AddArgument($Credential).AddArgument($db).AddArgument($LoginNamePattern)

            $runspace.RunspacePool = $runspacePool
            $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
        }

        foreach ($runspace in $runspaces) {
            $results = $runspace.Pipe.EndInvoke($runspace.Status)
            $runspace.Pipe.Dispose()

    foreach ($result in $results) {
        if ($result) {
            $result | Format-Table -Property DBName, UserType, UserName, DatabaseRole, Permission, PermissionState, ObjectType, SchemaName, ObjectName, ColumnName -AutoSize
            Write-Output "--------------------------------"
                }
            }
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }
}

 
# Define the function for creating a login
function Create-Login {
    param($Server, $Credential, $LoginName, $Password, $LoginNamePattern)
    $searchLoginQuery = "SELECT name FROM sys.server_principals WHERE name LIKE '$LoginNamePattern';"
    $existingLogin = Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $searchLoginQuery
    if ($existingLogin) {
        Write-Output "Login $LoginName already exists."
    } else {
        $createLoginQuery = "CREATE LOGIN [$LoginName] WITH PASSWORD = N'$Password';"
        Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $createLoginQuery

        $PasswordPolicyLoginQuery = "Alter LOGIN [$LoginName] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;"
        Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $PasswordPolicyLoginQuery

        $MustChangeLoginQuery = "Alter LOGIN [$LoginName] WITH PASSWORD = N'$Password' MUST_CHANGE"
        Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $MustChangeLoginQuery
        Write-Output "Login $LoginName created."
    }
}
# Updated function for checking login existence using Invoke-DbaQuery
function Check-LoginExistence {
    param(
        $Server,
        $Credential,
        $LoginName
    )
    $query = "SELECT name FROM sys.server_principals WHERE name = '$LoginName';"
    $result = Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Query $query
    return $result
}
# Define the function for dropping a login
function Drop-Login {
    param(
        $Server,
        $Credential,
        $LoginName,
        $IsServiceAccount = $false
    )
    $existsCheckQuery = "SELECT name FROM sys.server_principals WHERE name = '$LoginName';"
    $exists = Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $existsCheckQuery
    
    if ($exists.Count -eq 0) {
        Write-Output "Login $LoginName does not exist. No need to drop."
        return
    }
        
    # If createNewLoginFlag is on, do not proceed with dropping the login
    if ($createNewLoginFlag) {
        Write-Output "Cannot drop login $LoginName because createNewLoginFlag is set to true."
        return
    }

    # If service account, first remove from the specific table
    if ($IsServiceAccount) {
        $removeQuery = "DELETE FROM APSAccountInfo.dbo.APSserviceAccounts_DBA WHERE name = '$LoginName';"
        Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Query $removeQuery
        Write-Output "Service account $LoginName removed from APSserviceAccounts_DBA."
    }

    $dropLoginQuery = "DROP LOGIN [$LoginName];"
    Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $dropLoginQuery
    Write-Output "Login $LoginName dropped."
}

# Define the function for resetting a password
function Reset-Password {
    param($Server, $Credential, $LoginName, $Password)
    $resetPasswordQuery = "ALTER LOGIN [$LoginName] WITH PASSWORD = N'$Password';"
    Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $resetPasswordQuery
    Write-Output "Password for $LoginName reset."
    
    # Enable and unlock the account after resetting the password
    Enable-Account -Server $Server -Credential $Credential -LoginName $LoginName
    Unlock-Account -Server $Server -Credential $Credential -LoginName $LoginName
    
     Write-Output "Login $LoginName Unlocked."
}

function Manage-AccountStatus {
    param(
        $Server,
        $Credential,
        $LoginName,
        [ValidateSet('Unlock', 'Disable', 'Enable')]
        $Action
    )
    switch ($Action) {
        'Unlock' {
            $query = "ALTER LOGIN [$LoginName] WITH CHECK_POLICY = OFF; ALTER LOGIN [$LoginName] WITH CHECK_POLICY = ON;"
            Write-Output "Login $LoginName unlocked."
        }
        'Disable' {
            $query = "ALTER LOGIN [$LoginName] DISABLE;"
            Write-Output "Login $LoginName disabled."
        }
        'Enable' {
            $query = "ALTER LOGIN [$LoginName] ENABLE;"
            Write-Output "Login $LoginName enabled."
        }
    }
    Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $query
}

# Define the function for granting database permissions
function Grant-DatabasePermissions {
    param($Server, $Credential, $LoginName, $DatabaseAccessList, $dbRoleNames)
    if ($DatabaseAccessList -eq "all") {
        $DatabaseAccessList = Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Query "SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0" | ForEach-Object { $_.name }
    }
    foreach ($Database in $DatabaseAccessList) {
        foreach ($Role in $dbRoleNames) {
            $grantPermissionsQuery = "EXEC sp_addrolemember '$Role','$LoginName'"
            Execute-Query -Server $Server -Credential $Credential -Database $Database -Query $grantPermissionsQuery
                    Write-Output "Granted $Role role to $LoginName in $Database."

	}
	
    }
}

# Define the function for revoking database permissions
function Revoke-DatabasePermissions {
    param($Server, $Credential, $LoginName, $DatabaseAccessList, $dbRoleNames)
    if ($DatabaseAccessList -eq "all") {
        $DatabaseAccessList = Invoke-DbaQuery -SqlInstance $Server -SqlCredential $Credential -Query "SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0" | ForEach-Object { $_.name }
    }
    foreach ($Database in $DatabaseAccessList) {
        foreach ($Role in $dbRoleNames) {
            $revokePermissionsQuery = "EXEC sp_droprolemember '$Role','$LoginName'"
            Execute-Query -Server $Server -Credential $Credential -Database $Database -Query $revokePermissionsQuery
        }
    }
}

# Define the function for granting schema permissions with enhanced logging
function Grant-SchemaPermissions {
    param(
        $Server,
        $Credential,
        $LoginName,
        $SchemaAccessList,
        $SchemaPermissionList,
        $DatabaseName  # Added parameter for database name
    )
    foreach ($Schema in $SchemaAccessList) {
        foreach ($Permission in $SchemaPermissionList) {
            $checkSchemaQuery = "SELECT 1 FROM sys.schemas WHERE name = '$Schema';"
            $schemaExists = Execute-Query -Server $Server -Credential $Credential -Database $DatabaseName -Query $checkSchemaQuery
            if ($schemaExists.Count -eq 0) {
                Write-Host "Schema '$Schema' does not exist in database '$DatabaseName'. Skipping permission grant for $LoginName."
            } else {
                $grantSchemaPermissionsQuery = "GRANT $Permission ON SCHEMA::$Schema TO [$LoginName];"
                Execute-Query -Server $Server -Credential $Credential -Database $DatabaseName -Query $grantSchemaPermissionsQuery
                Write-Host "Granted $Permission permission on schema $Schema to $LoginName in database $DatabaseName."
            }
        }
    }
}

# Define the function for granting object permissions
function Grant-ObjectPermissions {
    param($Server, $Credential, $LoginName, $ObjectAccessList, $PermissionObjectAccessList)
    foreach ($Object in $ObjectAccessList) {
        foreach ($Permission in $PermissionObjectAccessList) {
            # Check if the object exists
            $checkObjectQuery = "SELECT 1 FROM sys.objects WHERE name = '$Object';"
            $objectExists = Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $checkObjectQuery
            if ($objectExists) {
                $grantObjectPermissionsQuery = "GRANT $Permission ON $Object TO [$LoginName];"
                Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $grantObjectPermissionsQuery
		            Write-Output "Granted $Permission permission on $Object to $LoginName in $Database."

            } else {
                Write-Host "Object '$Object' does not exist. Skipping permission grant."
            }
        }
    }
}

# Define the function for sending an email notification (Updated with dynamic subject selection)
function Send-EmailNotification {
    param(
        $Server, 
        $ActionDetails, 
        $ccAddress,  # Use this as needed
        $ActionType  # Added to differentiate the action types
    )
    
    # Initialize variables
    $emailSubject = $null
    $emailBody = $null

    # Determine email subject and body based on action type
    switch ($ActionType) {
        'ResetPassword' {
            $emailSubject = "APS Account Password Reset"
        $emailBody = @"
        <html>
        <body>
            <p>Hello,</p>
            <p>Per your request, your APS Account: <strong>$loginName</strong> has been reset to a temporary password <strong>$resetPassword</strong>.</p>
            <p>You need to change the password prior to using the account. Please use <a href='https://midas.us.baesystems.com/UserCommunity/SiteAssets/HowToWiki/Change APS Password/APS Password Change Tool.xlsm'>this tool</a> to change your password.</p>
            <p>After you’ve changed the password, it is critical to update the password everywhere it is used before refreshing any reports/dashboards in order to avoid locking the account out.</p>
            <p>Be sure to Update your Cached Credentials in PowerBI Desktop and also update your credentials on any published reports you’ve used these credentials on.</p>
            <p>You can use the “Report Data Sources” tab of <a href='https://midas-pbi.us.baesystems.com/reports/powerbi/Cross_Sector/Midas Dashboard Management'>this report</a> to view all of the reports you have published.</p>
            <p><a href='https://midas.us.baesystems.com/UserCommunity/HowToWiki/Change APS Password.aspx'>APS Account Password Change / Reset Instructions</a></p>
            <p>For more help, please contact <a href='mailto:dless.csbianalystics@baesystems.com'>dless.csbianalystics@baesystems.com</a></p>
            <p>Thanks</p>
        </body>
        </html>
"@
    }
        'CreateLogin' {
            $emailSubject = "New SQL Server Account Created"
        # Customize this body for the new login scenario as needed
        $emailBody = @"
        <html>
        <body>
            <h2>Welcome to APS</h2>
            <p>A new account has been created for you. Your username is: <strong>$loginName</strong></p>
            <p>Please follow the instructions sent in a separate email to set up your account password.</p>
            <p>If you encounter any issues, contact support at <a href='mailto:support@example.com'>dless.csbianalystics@baesystems.com</a>.</p>
            <p>Thanks</p>
        </body>
        </html>
"@
    }
    else {
            $emailSubject = "SQL Server Account Management Notification"
        # Default email body for other types of notifications
        $emailBody = @"
        <html>
        <head>
            <style>
                body {font-family: Arial, sans-serif; font-size: 14px;}
            </style>
        </head>
        <body>
            <h2>Login Process Report</h2>
            <p>$ActionDetails</p>
            <p><strong>Server:</strong> $Server</p>
            <p><strong>Date:</strong> $(Get-Date)</p>
        </body>
        </html>
"@
    }
    }

    if ($sendEmailFlag) {
        $message = New-Object System.Net.Mail.MailMessage
        $message.From = [System.Net.Mail.MailAddress]::new($fromAddress)
        $message.To.Add($toAddress)
        if ($ccAddress) {
            $message.CC.Add($ccAddress)  # Add CC recipients if provided
        }
        $message.Subject = $emailSubject
        $message.IsBodyHtml = $true
        $message.Body = $emailBody

        $smtpClient = New-Object System.Net.Mail.SmtpClient($smtpServer, 25)
        $smtpClient.EnableSsl = $false
        try {
            $smtpClient.Send($message)
            Write-Host "Email notification sent."
        } catch {
            Write-Host "Failed to send email notification: $_"
        }
    } else {
        Write-Host "Email notifications are disabled. No email sent."
    }
}

# Define the function for the main login process
function Manage-Login {
    param(
        $Server, 
        $Credential, 
        $LoginName, 
        $Password, 
        $IsServiceAccount, 
        $SchemaAccessList, 
        $SchemaPermissionList, 
        $ObjectAccessList, 
        $PermissionObjectAccessList,
        $DatabaseAccessList, 
        $DbRoleNames
    )
    $ActionDetails = ""
    $ActionType = ""
    $SendEmail = $false  # Initialize SendEmail flag to false

    # Handle report generation
    if ($ReportFlag) {
        Generate-Report -Server $Server -Credential $Credential -LoginNamePattern $LoginNamePattern -ReportFlag $ReportFlag
        return
    }

    # Process for creating new login and service account
    if ($createNewLoginFlag) {
        $existingLogin = Get-DbaLogin -SqlInstance $Server -SqlCredential $Credential -Login $LoginName
        if (-not $existingLogin) {
            Create-Login -Server $Server -Credential $Credential -LoginName $LoginName -Password $Password
            $ActionDetails += "Login '$LoginName' created.`n"
            $ActionType = "CreateLogin"
            $SendEmail = $true  # Set SendEmail to true for new login creation
            
            if ($IsServiceAccount) {
                $insertQuery = "INSERT INTO APSAccountInfo.dbo.APSserviceAccounts_DBA (POC, name, LoadDate) VALUES ('$requesterEmail', '$LoginName', '$date')"
                Execute-Query -Server $Server -Credential $Credential -Database 'master' -Query $insertQuery
                $ActionDetails += "Service account for '$LoginName' created.`n"
                $ActionType += "/ServiceAccountCreation"
            }

            Grant-DatabasePermissions -Server $Server -Credential $Credential -LoginName $LoginName -DatabaseAccessList $DatabaseAccessList -DbRoleNames $DbRoleNames
            Grant-SchemaPermissions -Server $Server -Credential $Credential -LoginName $LoginName -SchemaAccessList $SchemaAccessList -SchemaPermissionList $SchemaPermissionList
            Grant-ObjectPermissions -Server $Server -Credential $Credential -LoginName $LoginName -ObjectAccessList $ObjectAccessList -PermissionObjectAccessList $PermissionObjectAccessList
        } else {
            $ActionDetails += "Login '$LoginName' already exists.`n"
        }
    }

    # Handle reset password, unlock, disable, enable, and delete login actions here

    if ($resetPasswordFlag) {
        Reset-Password -Server $Server -Credential $Credential -LoginName $LoginName -Password $resetPassword
    $ActionDetails += "Password for '$LoginName' reset.`n"
         $ActionType = "ResetPassword"
        $SendEmail = $tru
    }

    # Perform actions without email notifications
    if ($unlockAccountFlag) {
Manage-AccountStatus -Server $server -Credential $credential -LoginName $LoginName -Action 'Unlock'
        $ActionDetails += "'$LoginName' account unlocked.`n"
    }

    if ($disableLoginFlag) {
Manage-AccountStatus -Server $server -Credential $credential -LoginName $LoginName -Action 'Disable'
        $ActionDetails += "'$LoginName' login disabled.`n"
    }

    if ($enableLoginFlag) {
Manage-AccountStatus -Server $server -Credential $credential -LoginName $LoginName -Action 'Enable'
        $ActionDetails += "'$LoginName' login enabled.`n"
    }

    if ($deleteLoginFlag) {
        Drop-Login -Server $Server -Credential $Credential -LoginName $LoginName
        $ActionDetails += "'$LoginName' login deleted.`n"
    }

    # Send email if needed and for specific actions
    if ($sendEmailFlag -and $SendEmail -and ($ActionType -eq "CreateLogin" -or $ActionType -eq "ResetPassword")) {

            Send-EmailNotification -Server $Server -ActionDetails $ActionDetails -ccAddress $ccAddress -ActionType $ActionType
    }

    }

# Main execution logic
if ($ReportFlag) {
    Generate-Report -Server $server -Credential $credential -LoginNamePattern $LoginNamePattern -ReportFlag $ReportFlag
} else {
    Manage-Login -Server $server -Credential $credential -LoginName $LoginName -Password $newLoginPassword -IsServiceAccount $createServiceAccountFlag -SchemaAccessList $schemaAccessList -SchemaPermissionList $schemaPermissionList -ObjectAccessList $objectAccessList -PermissionObjectAccessList $permissionObjectAccessList -DatabaseAccessList $databaseAccessList -DbRoleNames $dbRoleNames
}