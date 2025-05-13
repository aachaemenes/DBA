# CONFIGURATION SECTION - MODIFY THESE VALUES AS NEEDED
 
# OPERATION MODE - Set this to one of the following values:
# "REFRESH_MIRRORING_FROM_BACKUP" - Refresh mirroring using a backup (supports multiple databases)
# "REMOVE"  - Remove existing mirroring while preserving databases
# "FAILOVER" - Perform mirroring failover
# "EXTRACT" - Extract existing mirroring configuration from primary server
# "EMERGENCY_RECOVERY" - Recover databases stuck in mirroring/restoring state (use with caution)
# "CHANGE_ENDPOINT_OWNER" - Change the owner of the mirroring endpoint
# "ADD_WITNESS" - Add a witness server to existing mirroring setup
# "SET_MIRRORING_TIMEOUT" - Set the partner timeout value for mirrored databases
# "REFRESH_MIRRORING_ENDPOINT" - Refresh mirroring endpoints without changing database state
# "REMOVE_WITNESS" - Remove witness server from existing mirroring setup
# "REMOVE_REFRESH_ENDPOINT" - Force drop and recreate mirroring endpoints regardless of current settings
$OPERATION_MODE = "ADD_WITNESS"
 
# For EMERGENCY_RECOVERY mode, specify the server to recover
$EMERGENCY_SERVER = "" # Example: "smrtopt01sql11.bentleyhosting.com"
 
# SERVER INFORMATION
$PRIMARY_SERVER = "principal server name"   # Primary server name with FQDN
$MIRROR_SERVER = "mirror server name"    # Mirror server name with FQDN
$WITNESS_SERVER = "witness server name# Witness server name with FQDN (leave empty if no witness)
 
# DATABASE SETTINGS
$DATABASE_LIST = "ALL"  
$EXCLUDED_DATABASES = "master,tempdb,model,msdb,distribution,DBATools
 
# MIRRORING SETTINGS
$MIRRORING_PORT = 5022  # Default mirroring port
$ENDPOINT_ENCRYPTION = "Required" # Options: "Disabled", "Required", "Supported"
$ENCRYPTION_ALGORITHM = "AES"     # Options: "Aes", "AesRC4", "None", "RC4", "RC4Aes"
$ENDPOINT_NAME = "Mirroring"      # Name of the mirroring endpoint to create
$MIRRORING_TIMEOUT = 30           # Timeout value in seconds for database mirroring partnerships
 
# BACKUP SETTINGS
$BACKUP_FOLDER = "\\$PRIMARY_SERVER\Backups"  # Network share accessible by all servers
$ALWAYS_CREATE_NEW_BACKUP = $true          # Always create new backup, don't rely on existing backup files
 
# RESTORE SETTINGS
$CUSTOM_FILE_MAPPING = @{}                  
$MAX_TRANSFER_SIZE = 4194304                # 4MB (multiple of 64KB)
$BLOCK_SIZE = 65536                         # 64KB
$BUFFER_COUNT = 50                          # Number of I/O buffers
 
# BACKUP CONFIGURATION
$ENABLE_BACKUP_COMPRESSION = $true    # Enable backup compression if available
$ENABLE_BACKUP_CHECKSUM = $true       # Enable backup checksum
$ENABLE_BACKUP_VERIFY = $false        # Verify backups after creation
$CREATE_BACKUP_FOLDER = $false        # Create folder structure for backups
 
# EXTRACT CONFIGURATION
$timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
$OUTPUT_FILE = Join-Path -Path $BACKUP_FOLDER -ChildPath "MirroringConfig_$($PRIMARY_SERVER)_$timestamp.txt"  # Output file for EXTRACT operation
 
# ADDITIONAL OPTIONS
$FORCE_OPERATION = $true     # Set to $true to skip confirmation prompts except for critical ones
 
# Setting session defaults
Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true
Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $false

#############################################################
# SCRIPT EXECUTION - NO NEED TO MODIFY BELOW THIS LINE      #
#############################################################

# Check if dbatools is installed, if not, attempt to install it
if (-not (Get-Module -ListAvailable -Name dbatools)) {
    Write-Warning "dbatools module not found. Attempting to install..."
    try {
        Install-Module -Name dbatools -Force -AllowClobber
    }
    catch {
        Write-Error "Failed to install dbatools. Please install manually using: Install-Module -Name dbatools -Force"
        exit
    }
}

# Import dbatools module and make sure it's globally available
Write-Host "Loading dbatools module..." -ForegroundColor Cyan
Import-Module dbatools -Force -DisableNameChecking

# Verify the module loaded correctly with a simple function test
try {
    # Test a simple dbatools function
    $null = Get-Command -Name "Get-DbaDatabase" -ErrorAction Stop
    Write-Host "dbatools module loaded successfully" -ForegroundColor Green
} 
catch {
    Write-Error "Failed to load required dbatools functions. Error: $_"
    Write-Host "Please ensure dbatools is properly installed with: Install-Module dbatools -Force" -ForegroundColor Red
    exit
}

# Initialize credential variables to null - using Windows Authentication
$PrimarySqlCredential = $null
$MirrorSqlCredential = $null
$WitnessSqlCredential = $null

# Helper function to fix NT AUTHORITY\NETWORKSERVICE to NT AUTHORITY\NETWORK SERVICE
function Fix-ServiceAccountName {
    param (
        [string]$AccountName
    )
    
    if ($AccountName -eq "NT AUTHORITY\NETWORKSERVICE") {
        return "NT AUTHORITY\NETWORK SERVICE"
    }
    # Handle Linux service accounts as well
    elseif ($AccountName -eq "LocalSystem" -or $AccountName -like "NT SERVICE\*") {
        return "NT AUTHORITY\SYSTEM"
    }
    else {
        return $AccountName
    }
}


function Remove-MirroringWitness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SqlInstance = $PRIMARY_SERVER,
        
        [Parameter(Mandatory = $false)]
        [string]$DatabaseList = $DATABASE_LIST,
        
        [Parameter(Mandatory = $false)]
        [string]$ExcludedDatabases = $EXCLUDED_DATABASES,
        
        [Parameter(Mandatory = $false)]
        [switch]$Confirm = (-not $FORCE_OPERATION)
    )
    
    Write-Host "=== Removing Database Mirroring Witness ===" -ForegroundColor Cyan
    
    # Get initial database list to process using the standard function
    $allDatabases = Get-DatabaseList -ServerInstance $SqlInstance -SpecifiedDatabases $DatabaseList -ExcludedDatabases $ExcludedDatabases
    
    if (-not $allDatabases -or $allDatabases.Count -eq 0) {
        Write-Host "No databases selected for witness removal." -ForegroundColor Yellow
        return $false
    }
    
    # ENHANCEMENT: Filter to only those with witnesses
    $databasesWithWitness = Get-DbaDbMirror -SqlInstance $SqlInstance | 
        Where-Object { -not [string]::IsNullOrEmpty($_.MirroringWitness) -and ($allDatabases -contains $_.Name) }
        
    if ($databasesWithWitness.Count -eq 0) {
        Write-Host "No databases with witness found among selected databases." -ForegroundColor Yellow
        return $true
    }
    
    # Extract just the database names for easier processing
    $databases = $databasesWithWitness | Select-Object -ExpandProperty Name
    
    Write-Host "Found $($databases.Count) database(s) with witness:" -ForegroundColor Yellow
    $databasesWithWitness | ForEach-Object {
        Write-Host "- $($_.Name): $($_.MirroringWitness)" -ForegroundColor Yellow
    }
    
    if ($Confirm) {
        $confirmResponse = Read-Host "Do you want to remove the witness server from these databases? (y/n)"
        if ($confirmResponse.ToLower().Trim() -ne "y" -and $confirmResponse.ToLower().Trim() -ne "yes") {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return $false
        }
    }
    
    $successCount = 0
    $failureCount = 0
    $results = @()
    
    foreach ($db in $databasesWithWitness) {
        Write-Host "Removing witness for database $($db.Name)..." -ForegroundColor Yellow
        
        try {
            Set-DbaDbMirror -SqlInstance $SqlInstance -Database $db.Name -State RemoveWitness -Confirm:$false
            
            Write-Host "Successfully removed witness for $($db.Name)" -ForegroundColor Green
            $successCount++
            $results += [PSCustomObject]@{
                Database = $db.Name
                Status = "Success"
                Message = "Witness removed successfully"
            }
        }
        catch {
            Write-Error "Failed to remove witness for database $($db.Name): $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $db.Name
                Status = "Failed"
                Message = $_.Exception.Message
            }
        }
    }
    
    # Display summary
    Write-Host "`n=== Witness Removal Summary ===" -ForegroundColor Cyan
    Write-Host "Total databases with witness: $($databasesWithWitness.Count)" -ForegroundColor White
    Write-Host "Successfully removed: $successCount" -ForegroundColor Green
    Write-Host "Failed to remove: $failureCount" -ForegroundColor Red
    
    # Display detailed results if there were failures
    if ($failureCount -gt 0) {
        Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
        $results | Format-Table -AutoSize
    }
    
    return ($failureCount -eq 0)
}

# Function to get SQL Server service account
function Get-SqlServiceAccount {
    param (
        [string]$ServerInstance
    )
    
    try {
        # Extract computer name from server instance
        $computerName = $ServerInstance.Split('\')[0].Split('.')[0]
        
        # Use Get-DbaService to get the SQL Server service account
        $sqlService = Get-DbaService -ComputerName $computerName -Type Engine -ErrorAction Stop
        
        if ($sqlService) {
            # Get the service account name and fix it if needed
            $serviceAccount = Fix-ServiceAccountName -AccountName $sqlService.StartName
            Write-Host "SQL Service Account for $ServerInstance is : $serviceAccount" -ForegroundColor Green
            return $serviceAccount
        } else {
            Write-Warning "Could not determine SQL Service account for $ServerInstance. Using default SA account."
            return "sa"
        }
    }
    catch {
        Write-Warning "Error getting SQL Service account for $ServerInstance. Using default SA account. Error: $_"
        return "sa"
    }
}

# Function to clean up backup files after successful mirroring
function Remove-MirroringBackupFiles {
    param (
        [string]$Database,
        [string]$BackupFolder
    )
    
    Write-Host "Cleaning up backup files for database '$Database'..." -ForegroundColor Yellow
    
    try {
        # Find and remove backup files for this database
        $backupFiles = Get-ChildItem -Path $BackupFolder -Filter "$Database*.bak" -ErrorAction SilentlyContinue
        $logFiles = Get-ChildItem -Path $BackupFolder -Filter "$Database*.trn" -ErrorAction SilentlyContinue
        
        $totalFiles = @($backupFiles) + @($logFiles)
        
        if ($totalFiles.Count -gt 0) {
            Write-Host "Found $($totalFiles.Count) backup/log files to remove" -ForegroundColor Yellow
            
            foreach ($file in $totalFiles) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Host "Successfully removed: $($file.Name)" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not remove file $($file.Name): $_"
                }
            }
            
            Write-Host "Backup cleanup completed for database '$Database'" -ForegroundColor Green
        }
        else {
            Write-Host "No backup files found for database '$Database'" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Error during backup cleanup: $_"
    }
}

# Modified function to ensure service account exists as a login
function Ensure-ServiceAccountLogin {
    param (
        [string]$SqlInstance,
        [string]$ServiceAccount
    )
    
    try {
        # Check if login exists
        $loginExists = Get-DbaLogin -SqlInstance $SqlInstance -Login $ServiceAccount -ErrorAction SilentlyContinue
            
        if (-not $loginExists) {
            Write-Host "Service account login '$ServiceAccount' does not exist. Creating..." -ForegroundColor Yellow
            
            # Create the login - without specifying LoginType parameter which was causing issues
            try {
                # Simplified command that works for both Windows accounts and SQL accounts
                New-DbaLogin -SqlInstance $SqlInstance -Login $ServiceAccount -ErrorAction Stop
                Write-Host "Successfully created login for service account '$ServiceAccount'" -ForegroundColor Green
                
                # Grant server admin permission if SQL service account
                if ($ServiceAccount -like '*SQLServer*' -or $ServiceAccount -like '*MSSQL*') {
                    Write-Host "Granting sysadmin server role to SQL service account '$ServiceAccount'..." -ForegroundColor Yellow
                    Add-DbaServerRoleMember -SqlInstance $SqlInstance -ServerRole sysadmin -Login $ServiceAccount
                    Write-Host "Successfully granted sysadmin role to '$ServiceAccount'" -ForegroundColor Green
                }
                
                return $true
            }
            catch {
                Write-Warning "Could not create login using New-DbaLogin: $_"
                return $false
            }
        }
        else {
            Write-Host "Service account login '$ServiceAccount' already exists." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Warning "Error ensuring service account login: $_"
        return $false
    }
}

function Get-DatabaseList {
    param (
        [string]$ServerInstance,
        [string]$SpecifiedDatabases,
        [string]$ExcludedDatabases
    )
    
    # Get excluded databases array (without hardcoded system DBs)
    $excludeList = @()
    if (-not [string]::IsNullOrWhiteSpace($ExcludedDatabases)) {
        $excludeList = $ExcludedDatabases.Split(',').Trim()
    }
    
    Write-Host "Excluded databases: $($excludeList -join ', ')" -ForegroundColor Yellow
    
    # Test connection to server
    try {
        Write-Host "Testing connection to $ServerInstance..." -ForegroundColor Yellow
        $testConnection = Connect-DbaInstance -SqlInstance $ServerInstance -ErrorAction Stop
        Write-Host "Successfully connected to $ServerInstance" -ForegroundColor Green
    }
    catch {
        Write-Error "Authentication failed for $ServerInstance. Please check credentials and ensure server is available."
        Write-Error ("Error details: " + $_)
        return @()
    }
    
    # If empty string or "ALL" is specified, get all user databases excluding specified exclusions
    if ([string]::IsNullOrWhiteSpace($SpecifiedDatabases) -or $SpecifiedDatabases -eq "ALL") {
        try {
            Write-Host "Getting ALL user databases from $ServerInstance (excluding system and specified exclusions)..." -ForegroundColor Yellow
            
            # Get all user databases (always excluding system DBs)
            $allDatabases = Get-DbaDatabase -SqlInstance $ServerInstance -ExcludeSystem -ErrorAction Stop | 
                Where-Object { $excludeList -notcontains $_.Name } | 
                Select-Object -ExpandProperty Name
            
            $databases = $allDatabases
        }
        catch {
            Write-Error ("Failed to get databases from $ServerInstance. Error: " + $_)
            return @()
        }
    }
    else {
        # Get specified databases excluding the excluded ones
        $specifiedList = $SpecifiedDatabases.Split(',').Trim()
        $databases = @()
        
        foreach ($dbName in $specifiedList) {
            if ($excludeList -contains $dbName) {
                Write-Host "Database $dbName is in the exclusion list and will be skipped." -ForegroundColor Yellow
                continue
            }
            
            # Check if the database exists, using ExcludeSystem to automatically skip system DBs
            $db = Get-DbaDatabase -SqlInstance $ServerInstance -Database $dbName -ExcludeSystem -ErrorAction SilentlyContinue
            
            if ($db) {
                $databases += $dbName
                Write-Host "Added database $dbName to processing list." -ForegroundColor Green
            } else {
                Write-Warning "Database $dbName does not exist on $ServerInstance or is a system database and will be skipped."
            }
        }
    }
    
    # Final check and summary
    if ($databases.Count -eq 0) {
        Write-Warning "No databases selected for processing after applying exclusions."
        return @() # Return empty array instead of null
    }
    
    Write-Host "Selected $($databases.Count) databases for processing: $($databases -join ', ')" -ForegroundColor Cyan
    return $databases
}

function Write-DebugOutput {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch ($Level) {
            "INFO" { "Cyan" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            default { "White" }
        }
    )
}

function Set-EndpointOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SqlInstance,
        
        [Parameter(Mandatory = $false)]
        [string]$EndpointName = $ENDPOINT_NAME,
        
        [Parameter(Mandatory = $false)]
        [string]$OwnerName,
        
        [switch]$CreateLoginIfNotExists = $true,
        
        [switch]$Force = $FORCE_OPERATION
    )
    
    Write-Host "=== Setting Endpoint Owner ===" -ForegroundColor Cyan
    Write-Host "SQL Server: $SqlInstance" -ForegroundColor Yellow
    Write-Host "Endpoint: $EndpointName" -ForegroundColor Yellow
    
    try {
        # Get service account if OwnerName not specified
        if ([string]::IsNullOrWhiteSpace($OwnerName)) {
            $OwnerName = Get-SqlServiceAccount -ServerInstance $SqlInstance
            Write-Host "Using SQL Service Account as owner: $OwnerName" -ForegroundColor Yellow
        }
        
        Write-Host "New Owner: $OwnerName" -ForegroundColor Yellow
        
        # 1. Verify the endpoint exists
        $endpoint = Get-DbaEndpoint -SqlInstance $SqlInstance -Endpoint $EndpointName -ErrorAction Stop
        
        if (-not $endpoint) {
            # Try to create the endpoint if it doesn't exist
            if ($Force -or (Read-Host "Endpoint '$EndpointName' not found. Create it? (y/n)").ToLower() -eq 'y') {
                Write-Host "Creating new mirroring endpoint..." -ForegroundColor Yellow
                $endpoint = New-DbaEndpoint -SqlInstance $SqlInstance -Type DatabaseMirroring -Port $MIRRORING_PORT -EndpointEncryption $ENDPOINT_ENCRYPTION -EncryptionAlgorithm $ENCRYPTION_ALGORITHM -Role Partner -Name $EndpointName
                Write-Host "Successfully created mirroring endpoint" -ForegroundColor Green
            }
            else {
                Write-Error "Endpoint '$EndpointName' not found on server $SqlInstance"
                return $false
            }
        }
        else {
            Write-Host "Found endpoint: $($endpoint.Name) (Current owner: $($endpoint.Owner))" -ForegroundColor Green
        }
        
        # 2. Create login for owner if it doesn't exist and CreateLoginIfNotExists is true
        if ($CreateLoginIfNotExists) {
            Ensure-ServiceAccountLogin -SqlInstance $SqlInstance -ServiceAccount $OwnerName
        }
        
        # 3. Set the endpoint owner
        Write-Host "Setting endpoint owner to '$OwnerName'..." -ForegroundColor Yellow
        
        try {
            Set-DbaEndpoint -SqlInstance $SqlInstance -Endpoint $EndpointName -Owner $OwnerName
            Write-Host "Successfully set endpoint owner to '$OwnerName'" -ForegroundColor Green
            
            # Verify the change
            $updatedEndpoint = Get-DbaEndpoint -SqlInstance $SqlInstance -Endpoint $EndpointName
            
            if ($updatedEndpoint.Owner -eq $OwnerName) {
                Write-Host "Verified: Endpoint owner is now '$OwnerName'" -ForegroundColor Green
                return $true
            }
            else {
                Write-Warning "Owner change verification failed. Current owner is '$($updatedEndpoint.Owner)'"
                return $false
            }
        }
        catch {
            Write-Error "Failed to set endpoint owner: $_"
            return $false
        }
    }
    catch {
        Write-Error "Error during endpoint owner change operation: $_"
        return $false
    }
}

# NEW FUNCTION: Setup endpoint permissions between servers
function Setup-EndpointPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrimaryServer,
        
        [Parameter(Mandatory = $true)]
        [string]$MirrorServer,
        
        [Parameter(Mandatory = $false)]
        [string]$WitnessServer
    )
    
    Write-Host "Setting up endpoint permissions between servers..." -ForegroundColor Cyan
    
    try {
        # Extract computer names
        $primaryComputerName = $PrimaryServer.Split('\')[0].Split('.')[0]
        $mirrorComputerName = $MirrorServer.Split('\')[0].Split('.')[0]
        $witnessComputerName = $null
        if ($WitnessServer) {
            $witnessComputerName = $WitnessServer.Split('\')[0].Split('.')[0]
        }
        
        # Get domain info
        $computerInfo = Get-DbaComputerSystem -ComputerName $primaryComputerName
        $domain = $computerInfo.Domain.Split('.')[0]
        
        # Build account names
        $primaryAccount = "$domain\$primaryComputerName$"
        $mirrorAccount = "$domain\$mirrorComputerName$"
        $witnessAccount = $null
        if ($witnessComputerName) {
            $witnessAccount = "$domain\$witnessComputerName$"
        }
        
        Write-Host "Using the following computer accounts for permissions:" -ForegroundColor Yellow
        Write-Host "  Primary: $primaryAccount" -ForegroundColor Yellow
        Write-Host "  Mirror: $mirrorAccount" -ForegroundColor Yellow
        if ($witnessAccount) {
            Write-Host "  Witness: $witnessAccount" -ForegroundColor Yellow
        }
        
        # Grant permissions on primary server
        Write-Host "Granting permissions on primary server..." -ForegroundColor Yellow
        Ensure-ServiceAccountLogin -SqlInstance $PrimaryServer -ServiceAccount $mirrorAccount
        Grant-DbaAgPermission -SqlInstance $PrimaryServer -Type Endpoint -Login $mirrorAccount
        
        if ($witnessAccount) {
            Ensure-ServiceAccountLogin -SqlInstance $PrimaryServer -ServiceAccount $witnessAccount
            Grant-DbaAgPermission -SqlInstance $PrimaryServer -Type Endpoint -Login $witnessAccount
        }
        
        # Grant permissions on mirror server
        Write-Host "Granting permissions on mirror server..." -ForegroundColor Yellow
        Ensure-ServiceAccountLogin -SqlInstance $MirrorServer -ServiceAccount $primaryAccount
        Grant-DbaAgPermission -SqlInstance $MirrorServer -Type Endpoint -Login $primaryAccount
        
        if ($witnessAccount) {
            Ensure-ServiceAccountLogin -SqlInstance $MirrorServer -ServiceAccount $witnessAccount
            Grant-DbaAgPermission -SqlInstance $MirrorServer -Type Endpoint -Login $witnessAccount
        }
        
        # Grant permissions on witness server if applicable
        if ($WitnessServer) {
            Write-Host "Granting permissions on witness server..." -ForegroundColor Yellow
            Ensure-ServiceAccountLogin -SqlInstance $WitnessServer -ServiceAccount $primaryAccount
            Ensure-ServiceAccountLogin -SqlInstance $WitnessServer -ServiceAccount $mirrorAccount
            
            Grant-DbaAgPermission -SqlInstance $WitnessServer -Type Endpoint -Login $primaryAccount
            Grant-DbaAgPermission -SqlInstance $WitnessServer -Type Endpoint -Login $mirrorAccount
        }
        
        return $true
    }
    catch {
        Write-Error "Error setting up endpoint permissions: $_"
        return $false
    }
}

function Handle-OrphanedUsers {
    param (
        [string]$ServerInstance,
        [string]$Database,
        [switch]$Force,
        [switch]$DetailedOutput = $false,
        [switch]$RemoveNotExisting = $false
    )
    
    Write-Host "Checking for orphaned users in database '$Database' on $ServerInstance..." -ForegroundColor Yellow
    
    try {
        # Find orphaned users using dbatools
        $orphanedUsers = Get-DbaDbOrphanUser -SqlInstance $ServerInstance -Database $Database
        
        if ($orphanedUsers.Count -eq 0) {
            Write-Host "No orphaned users found in database '$Database' on $ServerInstance." -ForegroundColor Green
            return $true
        }
        
        Write-Host "Found $($orphanedUsers.Count) orphaned users in database '$Database' on $ServerInstance :" -ForegroundColor Yellow
        
        if ($DetailedOutput) {
            $orphanedUsers | Format-Table -AutoSize
        }
        else {
            # Changed from Name to User
            $orphanedUsers | Select-Object -ExpandProperty User | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
        }
        
        $repairUsers = $Force
        if (-not $Force) {
            $confirmRepair = Read-Host "Do you want to repair these orphaned users? (y/n)"
            $repairUsers = ($confirmRepair.ToLower().Trim() -eq "y" -or $confirmRepair.ToLower().Trim() -eq "yes")
        }
        
        if ($repairUsers) {
            Write-Host "Step 1: Repairing all orphaned users..." -ForegroundColor Yellow
            
            try {
                # First, attempt to repair all orphaned users
                $repairResult = Repair-DbaDbOrphanUser -SqlInstance $ServerInstance -Database $Database
                
                if ($repairResult -and $repairResult.Count -gt 0) {
                    Write-Host "Successfully repaired $($repairResult.Count) orphaned users:" -ForegroundColor Green
                    $repairResult | ForEach-Object { Write-Host "- $($_.OrphanUser) mapped to $($_.FixedUser)" -ForegroundColor Green }
                }
                else {
                    Write-Host "No users could be automatically repaired." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Warning "Error during orphaned user repair: $_"
            }
            
            # Check if we should remove remaining orphaned users
            if ($RemoveNotExisting) {
                Write-Host "Step 2: Removing users without matching logins..." -ForegroundColor Yellow
                
                try {
                    # Then, remove any remaining users that don't have matching logins
                    $removeResult = Repair-DbaDbOrphanUser -SqlInstance $ServerInstance -Database $Database -RemoveNotExisting
                    
                    if ($removeResult -and $removeResult.Count -gt 0) {
                        Write-Host "Successfully removed $($removeResult.Count) orphaned users without matching logins:" -ForegroundColor Green
                        $removeResult | ForEach-Object { Write-Host "- $($_.OrphanUser) removed" -ForegroundColor Green }
                    }
                    else {
                        Write-Host "No orphaned users removed." -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Warning "Error removing orphaned users: $_"
                }
            }
            
            # Final check for remaining orphaned users
            $remainingOrphans = Get-DbaDbOrphanUser -SqlInstance $ServerInstance -Database $Database
            
            if ($remainingOrphans.Count -gt 0) {
                Write-Host "There are still $($remainingOrphans.Count) orphaned users remaining in database '$Database'." -ForegroundColor Yellow
                $remainingOrphans | ForEach-Object { Write-Host "- $($_.User) (SID: $($_.Sid))" -ForegroundColor Yellow }
                Write-Host "Manual intervention may be required to fully resolve orphaned users." -ForegroundColor Yellow
                return $false
            }
            else {
                Write-Host "All orphaned users successfully handled in database '$Database'." -ForegroundColor Green
                return $true
            }
        }
        else {
            Write-Host "Orphaned users not repaired." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Error "Error handling orphaned users: $_"
        return $false
    }
}

function Set-MirroringTimeout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SqlInstance = $PRIMARY_SERVER,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutValue = $MIRRORING_TIMEOUT,
        
        [Parameter(Mandatory = $false)]
        [string]$DatabaseList = $DATABASE_LIST,
        
        [switch]$Force = $FORCE_OPERATION
    )
    
    Write-Host "=== Setting Database Mirroring Timeout ===" -ForegroundColor Cyan
    Write-Host "SQL Server: $SqlInstance" -ForegroundColor Yellow
    Write-Host "Timeout Value: $TimeoutValue seconds" -ForegroundColor Yellow
    
    try {
        # Test connection to server
        Write-Host "Testing connection to $SqlInstance..." -ForegroundColor Yellow
        $testConnection = Connect-DbaInstance -SqlInstance $SqlInstance -ErrorAction Stop
        Write-Host "Successfully connected to $SqlInstance" -ForegroundColor Green
        
        # Get all mirrored databases
        Write-Host "Getting mirrored databases..." -ForegroundColor Yellow
        $mirroredDatabases = @()
        
        # If no specific databases provided, get all mirrored databases
        if ([string]::IsNullOrWhiteSpace($DatabaseList) -or $DatabaseList -eq "ALL") {
            $mirroredDatabases = Get-DbaDbMirror -SqlInstance $SqlInstance | Select-Object -ExpandProperty Name
            
            if (-not $mirroredDatabases -or $mirroredDatabases.Count -eq 0) {
                Write-Host "No mirrored databases found on $SqlInstance" -ForegroundColor Yellow
                return $false
            }
            
            Write-Host "Found $($mirroredDatabases.Count) mirrored databases: $($mirroredDatabases -join ', ')" -ForegroundColor Green
        }
        else {
            # Use specified databases, but verify they have mirroring
            $dbList = $DatabaseList.Split(',').Trim()
            
            foreach ($dbName in $dbList) {
                $mirrorStatus = Get-DbaDbMirror -SqlInstance $SqlInstance -Database $dbName -ErrorAction SilentlyContinue
                
                if ($mirrorStatus) {
                    $mirroredDatabases += $dbName
                    Write-Host "Verified mirroring for database: $dbName" -ForegroundColor Green
                }
                else {
                    Write-Host "Database $dbName does not have mirroring configured. Skipping." -ForegroundColor Yellow
                }
            }
            
            if ($mirroredDatabases.Count -eq 0) {
                Write-Host "None of the specified databases have mirroring configured." -ForegroundColor Yellow
                return $false
            }
        }
        
        # Initialize counters
        $successCount = 0
        $failureCount = 0
        $results = @()
        
        # Process each mirrored database
        foreach ($dbName in $mirroredDatabases) {
            Write-Host "Setting timeout for database: $dbName to $TimeoutValue seconds..." -ForegroundColor Yellow
            
            try {
                # Use T-SQL to set the timeout
                $query = "ALTER DATABASE [$dbName] SET PARTNER TIMEOUT $TimeoutValue;"
                Invoke-DbaQuery -SqlInstance $SqlInstance -Database "master" -Query $query -ErrorAction Stop
                
                Write-Host "Successfully set timeout for $dbName to $TimeoutValue seconds" -ForegroundColor Green
                $successCount++
                $results += [PSCustomObject]@{
                    Database = $dbName
                    Status = "Success"
                    Message = "Timeout set to $TimeoutValue seconds"
                }
            }
            catch {
                Write-Error "Failed to set timeout for database $dbName : $_"
                $failureCount++
                $results += [PSCustomObject]@{
                    Database = $dbName
                    Status = "Failed"
                    Message = $_.Exception.Message
                }
            }
        }
        
        # Display summary
        Write-Host "`n=== Mirroring Timeout Update Summary ===" -ForegroundColor Cyan
        Write-Host "Total databases processed: $($mirroredDatabases.Count)" -ForegroundColor White
        Write-Host "Successfully updated: $successCount" -ForegroundColor Green
        Write-Host "Failed to update: $failureCount" -ForegroundColor Red
        
        # Display detailed results if needed
        if ($failureCount -gt 0) {
            Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
            $results | Format-Table -AutoSize
        }
        
        return ($failureCount -eq 0)
    }
    catch {
        Write-Error "Error during mirroring timeout update: $_"
        return $false
    }
}

function Refresh-CreateEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        
        [Parameter(Mandatory = $false)]
        [string]$EndpointName = $ENDPOINT_NAME,
        
        [Parameter(Mandatory = $false)]
        [int]$Port = $MIRRORING_PORT,
        
        [Parameter(Mandatory = $false)]
        [string]$Encryption = $ENDPOINT_ENCRYPTION,
        
        [Parameter(Mandatory = $false)]
        [string]$Algorithm = $ENCRYPTION_ALGORITHM,
        
        [Parameter(Mandatory = $false)]
        [string]$Role = "ALL", # ALL for principal/mirror, WITNESS for witness servers
        
        [Parameter(Mandatory = $false)]
        [bool]$PreservePermissions = $false, # Only true for witness servers
        
        [Parameter(Mandatory = $false)]
        [switch]$Force = $FORCE_OPERATION
    )
    
    Write-Host "=== Setting Up Database Mirroring Endpoint on $ServerInstance ===" -ForegroundColor Cyan
    
    try {
        # Step 1: Capture existing permissions before making any changes
        $existingPermissions = $null
        if ($PreservePermissions -or $Role -eq "WITNESS") {
            $existingPermissionsQuery = @"
SELECT 
    EP.name, 
    SP.state, 
    CONVERT(nvarchar(38), SUSER_NAME(SP.grantor_principal_id)) AS GRANTOR, 
    SP.type AS PERMISSION,
    CONVERT(nvarchar(46), SUSER_NAME(SP.grantee_principal_id)) AS GRANTEE 
FROM sys.server_permissions SP
JOIN sys.endpoints EP ON SP.major_id = EP.endpoint_id
WHERE EP.type_desc = 'DATABASE_MIRRORING';
"@
            $existingPermissions = Invoke-DbaQuery -SqlInstance $ServerInstance -Query $existingPermissionsQuery -ErrorAction SilentlyContinue
            
            if ($existingPermissions) {
                Write-Host "Found existing permissions on mirroring endpoint:" -ForegroundColor Yellow
                $existingPermissions | ForEach-Object {
                    Write-Host "  - $($_.GRANTEE) has $($_.PERMISSION) permission" -ForegroundColor Yellow
                }
            }
        }
        
        # Step 2: Check if endpoint exists and get current settings
        $existingEndpoint = Get-DbaEndpoint -SqlInstance $ServerInstance -Type DatabaseMirroring -ErrorAction SilentlyContinue
        $requiresRecreation = $false
        $currentSettings = @{}
        
        # For Witness servers, consider whether we always want to recreate
        if ($Role -eq "WITNESS" -and $Force) {
            $requiresRecreation = $true
            Write-Host "Witness endpoint with Force parameter - will force recreation regardless of settings" -ForegroundColor Yellow
        }
        
        if ($existingEndpoint) {
            Write-Host "Endpoint already exists on ${ServerInstance}: $($existingEndpoint.Name)" -ForegroundColor Green
            
            # Check detailed endpoint settings with the accurate query
            $endpointQuery = @"
USE master;
SELECT 
    name AS EndpointName,
    type_desc AS EndpointType,
    state_desc AS EndpointState,
    role_desc AS RoleType,
    is_encryption_enabled AS EncryptionEnabled,
    encryption_algorithm_desc AS EncryptionAlgorithm,
    CASE 
        WHEN is_encryption_enabled = 1 THEN 'Required'
        WHEN is_encryption_enabled = 0 AND encryption_algorithm_desc = 'NONE' THEN 'Disabled'
        WHEN is_encryption_enabled = 0 AND encryption_algorithm_desc != 'NONE' THEN 'Supported'
    END AS EncryptionStatus
FROM sys.database_mirroring_endpoints
WHERE type = 4; -- DATABASE_MIRRORING
"@
            $endpointDetails = Invoke-DbaQuery -SqlInstance $ServerInstance -Query $endpointQuery
            
            # Store current settings
            foreach ($row in $endpointDetails) {
                $currentSettings = @{
                    Name = $row.EndpointName
                    Port = $existingEndpoint.Port
                    Encryption = $row.EncryptionStatus
                    Algorithm = $row.EncryptionAlgorithm
                    Role = $row.RoleType
                }
            }
            
            # Compare with desired settings
            Write-Host "Comparing current endpoint settings with desired settings:" -ForegroundColor Yellow
            Write-Host "  Name: Current=$($currentSettings.Name), Desired=$EndpointName" -ForegroundColor Yellow
            Write-Host "  Port: Current=$($currentSettings.Port), Desired=$Port" -ForegroundColor Yellow
            Write-Host "  Encryption: Current=$($currentSettings.Encryption), Desired=$Encryption" -ForegroundColor Yellow
            Write-Host "  Algorithm: Current=$($currentSettings.Algorithm), Desired=$Algorithm" -ForegroundColor Yellow
            Write-Host "  Role: Current=$($currentSettings.Role), Desired=$Role" -ForegroundColor Yellow
            
            # Add role comparison logic - convert role parameter to database role type
            $desiredRoleType = if ($Role -eq "WITNESS") { "WITNESS" } else { "PARTNER" }
            $roleMatches = ($currentSettings.Role -eq $desiredRoleType)
            if (!$roleMatches) {
                Write-Host "  - Role mismatch detected: Current=$($currentSettings.Role), Desired=$desiredRoleType" -ForegroundColor Yellow
            }
            
            # Determine if recreation is needed - check name, port, encryption, algorithm, and role
            if ($currentSettings.Name -ne $EndpointName -or
                $currentSettings.Port -ne $Port -or 
                $currentSettings.Encryption -ne $Encryption -or 
                $currentSettings.Algorithm -ne $Algorithm.ToUpper() -or
                !$roleMatches) {
                
                $requiresRecreation = $true
                Write-Host "Settings mismatch detected - endpoint requires recreation" -ForegroundColor Red
                
                # Show which setting is mismatched
                if ($currentSettings.Name -ne $EndpointName) {
                    Write-Host "  - Endpoint name mismatch" -ForegroundColor Yellow
                }
                if ($currentSettings.Port -ne $Port) {
                    Write-Host "  - Port mismatch" -ForegroundColor Yellow
                }
                if ($currentSettings.Encryption -ne $Encryption) {
                    Write-Host "  - Encryption mismatch" -ForegroundColor Yellow
                }
                if ($currentSettings.Algorithm -ne $Algorithm.ToUpper()) {
                    Write-Host "  - Algorithm mismatch" -ForegroundColor Yellow
                }
                if (!$roleMatches) {
                    Write-Host "  - Role mismatch" -ForegroundColor Yellow
                }
                
                # Confirm if not in force mode
                if (-not $Force) {
                    $confirmRecreate = Read-Host "Endpoint settings differ. Recreate endpoint? (y/n)"
                    if ($confirmRecreate.ToLower().Trim() -ne "y" -and $confirmRecreate.ToLower().Trim() -ne "yes") {
                        Write-Host "Skipping endpoint recreation" -ForegroundColor Yellow
                        $requiresRecreation = $false
                    }
                }
            } else {
                Write-Host "Endpoint settings match desired configuration - no recreation needed" -ForegroundColor Green
            }
        } else {
            # No existing endpoint, need to create
            Write-Host "No existing mirroring endpoint found on $ServerInstance" -ForegroundColor Yellow
            $requiresRecreation = $true
        }
        
        # If recreation is needed, handle the process
        if ($requiresRecreation) {
            # Step 3: Find affected mirrored databases and their status
            $affectedDatabases = @()
            
            if ($existingEndpoint) {
                Write-Host "Getting list of mirrored databases affected by this endpoint..." -ForegroundColor Yellow
                
                # Get databases with mirroring configured using dbatools
                $mirroredDatabases = Get-DbaDbMirror -SqlInstance $ServerInstance -ErrorAction SilentlyContinue
                
                if ($mirroredDatabases -and $mirroredDatabases.Count -gt 0) {
                    # Store detailed mirroring status for each database
                    $affectedDatabases = $mirroredDatabases | Select-Object Name, MirroringStatus, MirroringPartner, MirroringWitness, MirroringRole
                    
                    Write-Host "Found $($affectedDatabases.Count) mirrored databases that will be affected:" -ForegroundColor Yellow
                    $affectedDatabases | ForEach-Object {
                        $roleInfo = if ($_.MirroringRole -eq 1) { "(Principal)" } elseif ($_.MirroringRole -eq 2) { "(Mirror)" } else { "" }
                        Write-Host "  - $($_.Name) (Status: $($_.MirroringStatus)) $roleInfo" -ForegroundColor Yellow
                    }
                    
                    # Step 4: Pause mirroring for all affected databases
                    Write-Host "Temporarily suspending mirroring for affected databases..." -ForegroundColor Yellow
                    
                    foreach ($db in $affectedDatabases) {
                        # Only suspend if database is in a synchronized state and not already suspended
                        if ($db.MirroringStatus -ne "Suspended" -and $db.MirroringStatus -ne "Disconnected") {
                            try {
                                Write-Host "  - Suspending mirroring for database $($db.Name)..." -ForegroundColor Yellow
                                # Use dbatools to suspend mirroring
                                Set-DbaDbMirror -SqlInstance $ServerInstance -Database $db.Name -State Suspend -Confirm:$false
                                Write-Host "  - Successfully suspended mirroring for database $($db.Name)" -ForegroundColor Green
                            } catch {
                                Write-Warning "Could not suspend mirroring for $($db.Name): $_"
                            }
                        } else {
                            Write-Host "  - Database $($db.Name) already in $($db.MirroringStatus) state, no need to suspend" -ForegroundColor Cyan
                        }
                    }
                    
                    # Give SQL Server a moment to complete the suspension
                    Write-Host "Waiting for suspension operations to complete..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                } else {
                    Write-Host "No mirrored databases found that would be affected by endpoint changes" -ForegroundColor Green
                }
                
                # Step 5: Drop existing endpoint
                Write-Host "Dropping existing mirroring endpoint '$($currentSettings.Name)'..." -ForegroundColor Yellow
                try {
                    # Use dbatools to drop the endpoint
                    Remove-DbaEndpoint -SqlInstance $ServerInstance -Endpoint $existingEndpoint.Name -Confirm:$false
                    Write-Host "Successfully dropped existing endpoint" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to drop existing endpoint: $_"
                    
                    # Try to resume mirroring for any suspended databases if drop failed
                    if ($affectedDatabases.Count -gt 0) {
                        Write-Host "Attempting to resume mirroring for affected databases due to error..." -ForegroundColor Yellow
                        foreach ($db in $affectedDatabases) {
                            try {
                                Set-DbaDbMirror -SqlInstance $ServerInstance -Database $db.Name -State Resume -Confirm:$false
                            } catch { }
                        }
                    }
                    return $null
                }
            }
            
            # Step 6: Create new endpoint with specified settings using T-SQL
            Write-Host "Creating new mirroring endpoint on $ServerInstance using T-SQL..." -ForegroundColor Yellow
            
            try {
                # Set the correct role based on the Role parameter
                $endpointRole = if ($Role -eq "WITNESS") {
                    "WITNESS"
                } else {
                    "PARTNER"
                }
                
                # Format the encryption setting
                $encryptionSetting = switch ($Encryption.ToUpper()) {
                    "REQUIRED" { "REQUIRED" }
                    "SUPPORTED" { "SUPPORTED" }
                    "DISABLED" { "DISABLED" }
                    default { "REQUIRED" }
                }
                
                # Format the algorithm setting
                $algorithmSetting = if ($encryptionSetting -eq "DISABLED") {
                    ""
                } else {
                    "ALGORITHM $Algorithm"
                }

                # Create the T-SQL command for endpoint creation
                $createEndpointSql = @"
CREATE ENDPOINT [$EndpointName]
STATE = STARTED
AS TCP (LISTENER_PORT = $Port, LISTENER_IP = ALL)
FOR DATA_MIRRORING (ROLE = $endpointRole, AUTHENTICATION = WINDOWS NEGOTIATE, ENCRYPTION = $encryptionSetting $algorithmSetting)
"@
                
                # Execute the T-SQL command
                Invoke-DbaQuery -SqlInstance $ServerInstance -Query $createEndpointSql -ErrorAction Stop
                Write-Host "Successfully created new endpoint '$EndpointName' with role '$endpointRole' using T-SQL" -ForegroundColor Green
                Write-Host "T-SQL used: $createEndpointSql" -ForegroundColor Gray
                
                # Step 7: Restart SQL Server service if this is a WITNESS server
                if ($Role -eq "WITNESS") {
                    Write-Host "This is a witness server. Restarting SQL Server service after endpoint creation..." -ForegroundColor Yellow
                    
                    try {
                        # Extract computer name from server instance
                        $computerName = $ServerInstance.Split('\')[0]
                        
                        Write-Host "Restarting SQL Server service on $computerName..." -ForegroundColor Yellow
                        
                        # Use SC command exclusively - remove all dbatools code
                        # Stop SQL Server service
                        Write-Host "Stopping SQL Server service using SC command..." -ForegroundColor Yellow
                        $stopResult = sc.exe \\$computerName stop MSSQLSERVER
                        Write-Host "Stop result: $stopResult"
                        
                        # Wait for service to fully stop using dynamic check
                        Write-Host "Waiting for SQL Server service to fully stop..." -ForegroundColor Yellow
                        $maxWaitStop = 30
                        $waitedStop = 0
                        do {
                            Start-Sleep -Seconds 2
                            $waitedStop += 2
                            $status = sc.exe \\$computerName query MSSQLSERVER
                            Write-Host "." -NoNewline
                        } while ($status -match "STOP_PENDING" -and $waitedStop -lt $maxWaitStop)
                        Write-Host ""
                        
                        # Start SQL Server service
                        Write-Host "Starting SQL Server service on $computerName..." -ForegroundColor Yellow
                        $startResult = sc.exe \\$computerName start MSSQLSERVER
                        Write-Host "Start result: $startResult"
                        
                        # Wait for SQL Server to fully initialize using dynamic check
                        Write-Host "Waiting for SQL Server to fully initialize..." -ForegroundColor Yellow
                        $maxWaitStart = 60
                        $waitedStart = 0
                        $connected = $false
                        
                        do {
                            Start-Sleep -Seconds 2
                            $waitedStart += 2
                            Write-Host "." -NoNewline
                            
                            try {
                                # Try to connect to the restarted instance
                                $conn = Connect-DbaInstance -SqlInstance $ServerInstance -ConnectTimeout 2 -ErrorAction Stop
                                $connected = $true
                                Disconnect-DbaInstance -SqlInstance $conn
                                Write-Host "`nSuccessfully connected to restarted witness server" -ForegroundColor Green
                                break
                            }
                            catch {
                                # Keep waiting until timeout
                            }
                        } while ($waitedStart -lt $maxWaitStart)
                        
                        if (-not $connected) {
                            Write-Host "Note: Could not verify connection to witness server after $maxWaitStart seconds. Continuing anyway..." -ForegroundColor Yellow
                        }
                    }
                    catch {
                        # General error handler
                        Write-Host "Note: Encountered issues while managing SQL service on witness server. Continuing anyway..." -ForegroundColor Yellow
                        Write-Host "This is typically not critical as long as the endpoint was created successfully." -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Error "Failed to create new endpoint: $_"
                return $null
            }
            
            # Step 8: Resume mirroring for previously affected databases
            if ($affectedDatabases.Count -gt 0) {
                Write-Host "Resuming mirroring for affected databases..." -ForegroundColor Yellow
                
                # Allow some time for the endpoint to be fully established
                Start-Sleep -Seconds 2
                
                foreach ($db in $affectedDatabases) {
                    # Only resume if it was previously synchronized and was suspended by us
                    if ($db.MirroringStatus -ne "Disconnected") {
                        try {
                            Write-Host "  - Resuming mirroring for database $($db.Name)..." -ForegroundColor Yellow
                            # Use dbatools to resume mirroring
                            Set-DbaDbMirror -SqlInstance $ServerInstance -Database $db.Name -State Resume -Confirm:$false
                            Write-Host "  - Successfully resumed mirroring for database $($db.Name)" -ForegroundColor Green
                        } catch {
                            Write-Warning "Could not resume mirroring for $($db.Name): $_"
                            Write-Host "    You may need to manually resume mirroring for this database" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host "  - Database $($db.Name) was disconnected before endpoint change, not attempting to resume" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Get the endpoint after creation/modification
        $endpoint = Get-DbaEndpoint -SqlInstance $ServerInstance -Type DatabaseMirroring -ErrorAction Stop
        
        # Step 9: Get SQL service account
        $serviceAccount = Get-SqlServiceAccount -ServerInstance $ServerInstance
        Write-Host "SQL Service Account for ${ServerInstance}: $serviceAccount" -ForegroundColor Green
        
        # Step 10: Ensure service account exists as login
        Ensure-ServiceAccountLogin -SqlInstance $ServerInstance -ServiceAccount $serviceAccount
        
        # Step 11: Set endpoint owner
        Write-Host "Setting endpoint owner to $serviceAccount..." -ForegroundColor Yellow
        $alterOwnerSql = "ALTER AUTHORIZATION ON ENDPOINT::[$EndpointName] TO [$serviceAccount]"
        Invoke-DbaQuery -SqlInstance $ServerInstance -Query $alterOwnerSql
        Write-Host "Endpoint owner set to $serviceAccount" -ForegroundColor Green
        
        # Step 12: Start endpoint (in case it's not already started)
        Write-Host "Ensuring endpoint is started on $ServerInstance..." -ForegroundColor Yellow
        $startEndpointSql = "ALTER ENDPOINT [$EndpointName] STATE = STARTED"
        Invoke-DbaQuery -SqlInstance $ServerInstance -Query $startEndpointSql
        Write-Host "Endpoint started successfully" -ForegroundColor Green
        
        # Step 13: Restore all existing permissions
        if ($existingPermissions -and ($PreservePermissions -or $Role -eq "WITNESS")) {
            Write-Host "Restoring existing endpoint permissions..." -ForegroundColor Yellow
            
            foreach ($perm in $existingPermissions) {
                try {
                    # Extract account name
                    $accountName = $perm.GRANTEE
                    
                    # Skip if account name is null or empty
                    if ([string]::IsNullOrWhiteSpace($accountName)) {
                        continue
                    }
                    
                    # Ensure account exists as login
                    Ensure-ServiceAccountLogin -SqlInstance $ServerInstance -ServiceAccount $accountName
                    
                    # Grant permission using dbatools
                    Write-Host "  - Restoring permission for $accountName..." -ForegroundColor Yellow
                    Grant-DbaAgPermission -SqlInstance $ServerInstance -Type Endpoint -Login $accountName
                    Write-Host "  - Permission restored for $accountName" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not restore permission for $($perm.GRANTEE): $_"
                }
            }
        }
        
        # Verify endpoint is properly configured and running
        $finalEndpoint = Get-DbaEndpoint -SqlInstance $ServerInstance -Type DatabaseMirroring | 
            Where-Object { $_.Name -eq $EndpointName }
            
        if ($finalEndpoint -and $finalEndpoint.EndpointState -eq "Started") {
            Write-Host "Endpoint configuration verified and endpoint is running" -ForegroundColor Green
        } else {
            Write-Warning "Endpoint may not be properly configured or is not running. Please check manually."
        }
        
        # Return the endpoint information
        return $finalEndpoint
    }
    catch {
        Write-Error "Error setting up endpoint on ${ServerInstance}: $_"
        return $null
    }
}

function Remove-Refresh-EndPoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrimaryServer,
        
        [Parameter(Mandatory = $true)]
        [string]$MirrorServer,
        
        [Parameter(Mandatory = $false)]
        [string]$WitnessServer,
        
        [Parameter(Mandatory = $false)]
        [string]$EndpointName = $ENDPOINT_NAME,
        
        [Parameter(Mandatory = $false)]
        [int]$Port = $MIRRORING_PORT,
        
        [Parameter(Mandatory = $false)]
        [string]$Encryption = $ENDPOINT_ENCRYPTION,
        
        [Parameter(Mandatory = $false)]
        [string]$Algorithm = $ENCRYPTION_ALGORITHM,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force = $FORCE_OPERATION
    )
    
    Write-Host "=== Force Removing and Recreating Database Mirroring Endpoints on All Servers ===" -ForegroundColor Cyan
    
    try {
        # Step 1: Verify server connections and collect information about all endpoints
        $servers = @($PrimaryServer, $MirrorServer)
        $hasWitnessServer = $false
        
        if (-not [string]::IsNullOrWhiteSpace($WitnessServer)) {
            $servers += $WitnessServer
            $hasWitnessServer = $true
        }
        
        # Dictionary to store permissions for each server
        $serverPermissions = @{}
        # Dictionary to store affected databases for each server
        $serverDatabases = @{}
        # Dictionary to store endpoint configurations for each server
        $serverEndpoints = @{}
        
        # Test connection to all servers first
        foreach ($server in $servers) {
            Write-Host "Testing connection to $server..." -ForegroundColor Yellow
            try {
                $connection = Connect-DbaInstance -SqlInstance $server -ErrorAction Stop
                Write-Host "Successfully connected to $server" -ForegroundColor Green
            }
            catch {
                throw "Failed to connect to $server. Please check credentials and ensure server is available. Error: $_"
            }
        }
        
        # Step 2: Collect permissions and database information from all servers
        foreach ($server in $servers) {
            # A) Collect endpoint permissions
            $permissionsQuery = @"
SELECT 
    EP.name, 
    SP.state, 
    CONVERT(nvarchar(38), SUSER_NAME(SP.grantor_principal_id)) AS GRANTOR, 
    SP.type AS PERMISSION,
    CONVERT(nvarchar(46), SUSER_NAME(SP.grantee_principal_id)) AS GRANTEE 
FROM sys.server_permissions SP
JOIN sys.endpoints EP ON SP.major_id = EP.endpoint_id
WHERE EP.type_desc = 'DATABASE_MIRRORING';
"@
            $existingPermissions = Invoke-DbaQuery -SqlInstance $server -Query $permissionsQuery -ErrorAction SilentlyContinue
            
            if ($existingPermissions) {
                Write-Host "Found existing permissions on mirroring endpoint for ${server}:" -ForegroundColor Yellow
                $existingPermissions | ForEach-Object {
                    Write-Host "  - $($_.GRANTEE) has $($_.PERMISSION) permission" -ForegroundColor Yellow
                }
                $serverPermissions[$server] = $existingPermissions
            } else {
                $serverPermissions[$server] = @()
            }
            
            # B) Collect affected mirrored databases
            $mirroredDatabases = Get-DbaDbMirror -SqlInstance $server -ErrorAction SilentlyContinue
            
            if ($mirroredDatabases -and $mirroredDatabases.Count -gt 0) {
                # Include databases that aren't disconnected or don't already have errors
                $affectedDatabases = $mirroredDatabases | Select-Object Name, MirroringStatus, MirroringPartner, MirroringWitness, MirroringRole
                
                Write-Host "Found $($affectedDatabases.Count) mirrored databases on ${server}:" -ForegroundColor Yellow
                $affectedDatabases | ForEach-Object {
                    $roleInfo = if ($_.MirroringRole -eq 1) { "(Principal)" } elseif ($_.MirroringRole -eq 2) { "(Mirror)" } else { "" }
                    Write-Host "  - $($_.Name) (Status: $($_.MirroringStatus)) $roleInfo" -ForegroundColor Yellow
                }
                
                $serverDatabases[$server] = $affectedDatabases
            } else {
                $serverDatabases[$server] = @()
            }
            
            # C) Collect current endpoint configuration
            $endpoint = Get-DbaEndpoint -SqlInstance $server -Type DatabaseMirroring -ErrorAction SilentlyContinue
            if ($endpoint) {
                $serverEndpoints[$server] = $endpoint
                Write-Host "Found existing endpoint on ${server}: $($endpoint.Name)" -ForegroundColor Green
            } else {
                $serverEndpoints[$server] = $null
            }
        }
        
        # Step 3: Suspend mirroring on ALL databases on PRIMARY server first
        Write-Host "Suspending mirroring for all affected databases from primary server..." -ForegroundColor Yellow
        
        $primaryDatabases = $serverDatabases[$PrimaryServer]
        if ($primaryDatabases -and $primaryDatabases.Count -gt 0) {
            foreach ($db in $primaryDatabases) {
                # Only suspend if database is in a synchronized state and not already suspended
                if ($db.MirroringStatus -ne "Suspended" -and $db.MirroringStatus -ne "Disconnected") {
                    try {
                        Write-Host "  - Suspending mirroring for database $($db.Name)..." -ForegroundColor Yellow
                        Set-DbaDbMirror -SqlInstance $PrimaryServer -Database $db.Name -State Suspend -Confirm:$false
                        Write-Host "  - Successfully suspended mirroring for database $($db.Name)" -ForegroundColor Green
                    } catch {
                        Write-Warning "Could not suspend mirroring for $($db.Name): $_"
                    }
                } else {
                    Write-Host "  - Database $($db.Name) already in $($db.MirroringStatus) state, no need to suspend" -ForegroundColor Cyan
                }
            }
            
            # Give SQL Server a moment to complete the suspension
            Write-Host "Waiting for suspension operations to complete..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
        
        # Step 4: Now drop all endpoints on all servers using dbatools
        foreach ($server in $servers) {
            $endpoint = $serverEndpoints[$server]
            if ($endpoint) {
                Write-Host "Dropping existing mirroring endpoint '$($endpoint.Name)' on $server..." -ForegroundColor Yellow
                try {
                    # Use dbatools to drop the endpoint
                    Remove-DbaEndpoint -SqlInstance $server -Endpoint $endpoint.Name -Confirm:$false
                    Write-Host "Successfully dropped existing endpoint on $server" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to drop existing endpoint on ${server}: $_"
                    # Continue with other servers anyway
                }
            } else {
                Write-Host "No existing mirroring endpoint found on $server" -ForegroundColor Yellow
            }
        }
        
        # Step 5: Create new endpoints on all servers using T-SQL
        foreach ($server in $servers) {
            Write-Host "Creating new mirroring endpoint on $server using T-SQL..." -ForegroundColor Yellow
            
            try {
                # Determine the role based on server type
                $endpointRole = if ($server -eq $WitnessServer) {
                    "WITNESS"
                } else {
                    "PARTNER"
                }
                
                # Format the encryption setting
                $encryptionSetting = switch ($Encryption.ToUpper()) {
                    "REQUIRED" { "REQUIRED" }
                    "SUPPORTED" { "SUPPORTED" }
                    "DISABLED" { "DISABLED" }
                    default { "REQUIRED" }
                }
                
                # Format the algorithm setting
                $algorithmSetting = if ($encryptionSetting -eq "DISABLED") {
                    ""
                } else {
                    "ALGORITHM $Algorithm"
                }

                # Create the T-SQL command for endpoint creation
                $createEndpointSql = @"
CREATE ENDPOINT [$EndpointName]
STATE = STARTED
AS TCP (LISTENER_PORT = $Port, LISTENER_IP = ALL)
FOR DATA_MIRRORING (ROLE = $endpointRole, AUTHENTICATION = WINDOWS NEGOTIATE, ENCRYPTION = $encryptionSetting $algorithmSetting)
"@
                # Execute the T-SQL command
                Invoke-DbaQuery -SqlInstance $server -Query $createEndpointSql -ErrorAction Stop
                Write-Host "Successfully created new endpoint '$EndpointName' with role '$endpointRole' on $server using T-SQL" -ForegroundColor Green
                Write-Host "T-SQL used: $createEndpointSql" -ForegroundColor Gray
                
                # Configure ownership and startup immediately
                $serviceAccount = Get-SqlServiceAccount -ServerInstance $server
                Write-Host "SQL Service Account for ${server}: $serviceAccount" -ForegroundColor Green
                
                # Ensure service account exists as login
                Ensure-ServiceAccountLogin -SqlInstance $server -ServiceAccount $serviceAccount
                
                # Set endpoint owner using T-SQL
                Write-Host "Setting endpoint owner to $serviceAccount on $server..." -ForegroundColor Yellow
                $alterOwnerSql = "ALTER AUTHORIZATION ON ENDPOINT::[$EndpointName] TO [$serviceAccount]"
                Invoke-DbaQuery -SqlInstance $server -Query $alterOwnerSql
                Write-Host "Endpoint owner set to $serviceAccount" -ForegroundColor Green
                
                # Start endpoint 
                Write-Host "Starting endpoint on $server..." -ForegroundColor Yellow
                $startEndpointSql = "ALTER ENDPOINT [$EndpointName] STATE = STARTED"
                Invoke-DbaQuery -SqlInstance $server -Query $startEndpointSql
                Write-Host "Endpoint started successfully on $server" -ForegroundColor Green
                
                # Restore permissions if any were stored
                $permissions = $serverPermissions[$server]
                if ($permissions -and $permissions.Count -gt 0) {
                    Write-Host "Restoring existing endpoint permissions on $server..." -ForegroundColor Yellow
                    
                    foreach ($perm in $permissions) {
                        try {
                            # Extract account name
                            $accountName = $perm.GRANTEE
                            
                            # Skip if account name is null or empty
                            if ([string]::IsNullOrWhiteSpace($accountName)) {
                                continue
                            }
                            
                            # Ensure account exists as login
                            Ensure-ServiceAccountLogin -SqlInstance $server -ServiceAccount $accountName
                            
                            # Grant permission using dbatools
                            Write-Host "  - Restoring permission for $accountName on $server..." -ForegroundColor Yellow
                            Grant-DbaAgPermission -SqlInstance $server -Type Endpoint -Login $accountName
                            Write-Host "  - Permission restored for $accountName" -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "Could not restore permission for $($perm.GRANTEE) on ${server}: $_"
                        }
                    }
                }
            }
            catch {
                Write-Error "Failed to create or configure new endpoint on ${server}: $_"
            }
        }
        
        # Step 6: If we have a witness server, restart its SQL Server service
        if ($hasWitnessServer) {
            Write-Host "Restarting SQL Server service on witness server after endpoint creation..." -ForegroundColor Yellow
            
            try {
                # Extract computer name from server instance
                $witnessComputerName = $WitnessServer.Split('\')[0]
                
                Write-Host "Restarting SQL Server service on $witnessComputerName..." -ForegroundColor Yellow
                
                # Use SC command exclusively - remove all dbatools code
                # Stop SQL Server service
                Write-Host "Stopping SQL Server service using SC command..." -ForegroundColor Yellow
                $stopResult = sc.exe \\$witnessComputerName stop MSSQLSERVER
                Write-Host "Stop result: $stopResult"
                
                # Wait for service to fully stop using dynamic check
                Write-Host "Waiting for SQL Server service to fully stop..." -ForegroundColor Yellow
                $maxWaitStop = 30
                $waitedStop = 0
                do {
                    Start-Sleep -Seconds 2
                    $waitedStop += 2
                    $status = sc.exe \\$witnessComputerName query MSSQLSERVER
                    Write-Host "." -NoNewline
                } while ($status -match "STOP_PENDING" -and $waitedStop -lt $maxWaitStop)
                Write-Host ""
                
                # Start SQL Server service
                Write-Host "Starting SQL Server service on $witnessComputerName..." -ForegroundColor Yellow
                $startResult = sc.exe \\$witnessComputerName start MSSQLSERVER
                Write-Host "Start result: $startResult"
                
                # Wait for SQL Server to fully initialize using dynamic check
                Write-Host "Waiting for SQL Server to fully initialize..." -ForegroundColor Yellow
                $maxWaitStart = 60
                $waitedStart = 0
                $connected = $false
                
                do {
                    Start-Sleep -Seconds 2
                    $waitedStart += 2
                    Write-Host "." -NoNewline
                    
                    try {
                        # Try to connect to the restarted instance
                        $conn = Connect-DbaInstance -SqlInstance $WitnessServer -ConnectTimeout 2 -ErrorAction Stop
                        $connected = $true
                        Disconnect-DbaInstance -SqlInstance $conn
                        Write-Host "`nSuccessfully connected to restarted witness server" -ForegroundColor Green
                        break
                    }
                    catch {
                        # Keep waiting until timeout
                    }
                } while ($waitedStart -lt $maxWaitStart)
                
                if (-not $connected) {
                    Write-Host "Note: Could not verify connection to witness server after $maxWaitStart seconds. Continuing anyway..." -ForegroundColor Yellow
                }
            }
            catch {
                # General error handler
                Write-Host "Note: Encountered issues while managing SQL service on witness server. Continuing anyway..." -ForegroundColor Yellow
                Write-Host "This is typically not critical as long as the endpoint was created successfully." -ForegroundColor Yellow
            }
        }
        
        # Step 7: Set up endpoint permissions between servers
        Write-Host "Setting up endpoint permissions between servers..." -ForegroundColor Yellow
        Setup-EndpointPermissions -PrimaryServer $PrimaryServer -MirrorServer $MirrorServer -WitnessServer $WitnessServer
        
        # Step 8: Resume mirroring for all previously affected databases
        Write-Host "Resuming mirroring for all affected databases..." -ForegroundColor Yellow
        
        # Allow time for endpoints to be fully established
        Write-Host "Waiting for all endpoints to be fully operational..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        
        $primaryDatabases = $serverDatabases[$PrimaryServer]
        if ($primaryDatabases -and $primaryDatabases.Count -gt 0) {
            foreach ($db in $primaryDatabases) {
                # Only resume if database wasn't already disconnected
                if ($db.MirroringStatus -ne "Disconnected") {
                    try {
                        Write-Host "  - Resuming mirroring for database $($db.Name)..." -ForegroundColor Yellow
                        Set-DbaDbMirror -SqlInstance $PrimaryServer -Database $db.Name -State Resume -Confirm:$false
                        Write-Host "  - Successfully resumed mirroring for database $($db.Name)" -ForegroundColor Green
                    } catch {
                        Write-Warning "Could not resume mirroring for $($db.Name): $_"
                        Write-Host "    You may need to manually resume mirroring for this database" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "  - Database $($db.Name) was disconnected before endpoint change, not attempting to resume" -ForegroundColor Yellow
                }
            }
        }
        
        # Step 9: Verify all endpoints are running
        Write-Host "Verifying all endpoints are running..." -ForegroundColor Yellow
        $allSuccess = $true
        
        foreach ($server in $servers) {
            $finalEndpoint = Get-DbaEndpoint -SqlInstance $server -Type DatabaseMirroring | 
                Where-Object { $_.Name -eq $EndpointName }
                
            if ($finalEndpoint -and $finalEndpoint.EndpointState -eq "Started") {
                Write-Host "Endpoint on $server is properly configured and running" -ForegroundColor Green
            } else {
                Write-Warning "Endpoint on $server may not be properly configured or is not running."
                $allSuccess = $false
            }
        }
        
        if ($allSuccess) {
            Write-Host "All endpoints successfully recreated and configured" -ForegroundColor Green
            
            # Verify mirroring status for a random database
            if ($primaryDatabases -and $primaryDatabases.Count -gt 0) {
                $sampleDb = $primaryDatabases[0].Name
                $status = Get-DbaDbMirror -SqlInstance $PrimaryServer -Database $sampleDb
                Write-Host "Sample mirroring status for ${sampleDb}: $($status.MirroringStatus)" -ForegroundColor Cyan
            }
        }
        
        return $allSuccess
    }
    catch {
        Write-Error "Error during endpoint removal/recreation: $_"
        return $false
    }
}

function Refresh-MirroringFromBackup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$PrimaryServer = $PRIMARY_SERVER,
        [Parameter(Mandatory = $false)]
        [string]$MirrorServer = $MIRROR_SERVER,
        [Parameter(Mandatory = $false)]
        [string]$WitnessServer = $WITNESS_SERVER,
        [Parameter(Mandatory = $false)]
        [string]$DatabaseList = $DATABASE_LIST,
        [Parameter(Mandatory = $false)]
        [string]$ExcludedDatabases = $EXCLUDED_DATABASES,
        [Parameter(Mandatory = $false)]
        [string]$BackupFolder = $BACKUP_FOLDER,
        [Parameter(Mandatory = $false)]
        [bool]$AlwaysCreateNewBackup = $ALWAYS_CREATE_NEW_BACKUP,
        [Parameter(Mandatory = $false)]
        [bool]$ForceOperation = $FORCE_OPERATION,
        [Parameter(Mandatory = $false)]
        [bool]$EnableCompression = $ENABLE_BACKUP_COMPRESSION,
        [Parameter(Mandatory = $false)]
        [bool]$EnableChecksum = $ENABLE_BACKUP_CHECKSUM,
        [Parameter(Mandatory = $false)]
        [bool]$EnableVerify = $ENABLE_BACKUP_VERIFY,
        [Parameter(Mandatory = $false)]
        [bool]$CreateFolder = $CREATE_BACKUP_FOLDER,
        [Parameter(Mandatory = $false)]
        [hashtable]$FileMapping = $CUSTOM_FILE_MAPPING,
        [Parameter(Mandatory = $false)]
        [int]$MaxTransferSize = $MAX_TRANSFER_SIZE,      
        [Parameter(Mandatory = $false)]
        [int]$BlockSize = $BLOCK_SIZE,              
        [Parameter(Mandatory = $false)]
        [int]$BufferCount = $BUFFER_COUNT
    )
    
    Write-Host "=== Refreshing Database Mirroring from Backup ===" -ForegroundColor Cyan
    Write-Host "Primary Server: $PrimaryServer" -ForegroundColor Yellow
    Write-Host "Mirror Server: $MirrorServer" -ForegroundColor Yellow
    Write-Host "Backup Folder: $BackupFolder" -ForegroundColor Yellow
    
    # Get database list to process
    $databases = Get-DatabaseList -ServerInstance $PrimaryServer -SpecifiedDatabases $DatabaseList -ExcludedDatabases $ExcludedDatabases
    
    if (-not $databases -or $databases.Count -eq 0) {
        Write-Host "No databases selected for mirroring refresh." -ForegroundColor Red
        return $false
    }
    
    Write-Host "Selected $($databases.Count) databases for processing: $($databases -join ', ')" -ForegroundColor Cyan
    
    # PART 1: Setup endpoints on all servers
    Write-Host "Setting up endpoints on all servers..." -ForegroundColor Cyan
    
    # Create/verify endpoint on primary
    $primaryEndpoint = Refresh-CreateEndpoint -ServerInstance $PrimaryServer -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Role "ALL" -PreservePermissions $false
    
    # Create/verify endpoint on mirror
    $mirrorEndpoint = Refresh-CreateEndpoint -ServerInstance $MirrorServer -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Role "ALL" -PreservePermissions $false
    
    # Create/verify endpoint on witness if specified
    if ($WitnessServer) {
        $witnessEndpoint = Refresh-CreateEndpoint -ServerInstance $WitnessServer -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Role "WITNESS" -PreservePermissions $true
    }
    
    # Setup permissions between all servers
    Setup-EndpointPermissions -PrimaryServer $PrimaryServer -MirrorServer $MirrorServer -WitnessServer $WitnessServer
    
    # Initialize counters
    $successCount = 0
    $failureCount = 0
    $results = @()
    
    # PART 2: Process each database
    foreach ($database in $databases) {
        Write-Host "`n== Processing database: $database ==" -ForegroundColor Cyan
        
        # Database validation and recovery model check
        $primaryDb = Get-DbaDatabase -SqlInstance $PrimaryServer -Database $database -ErrorAction SilentlyContinue
        
        if (-not $primaryDb) {
            Write-Error "Database $database doesn't exist on primary server $PrimaryServer. Skipping."
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Skipped" 
                Message = "Database does not exist on primary server"
            }
            continue
        }
        
        # Check recovery model using Get-DbaDbRecoveryModel
        $recoveryModel = Get-DbaDbRecoveryModel -SqlInstance $PrimaryServer -Database $database
        
        if ($recoveryModel.RecoveryModel -ne "Full") {
            Write-Host "Database $database is in $($recoveryModel.RecoveryModel) recovery model. Changing to Full..." -ForegroundColor Yellow
            Set-DbaDbRecoveryModel -SqlInstance $PrimaryServer -Database $database -RecoveryModel Full -Confirm:$false
            
            # Take full backup after recovery model change
            Write-Host "Taking full backup after recovery model change..." -ForegroundColor Yellow
            $recoveryModelBackup = Backup-DbaDatabase -SqlInstance $PrimaryServer -Database $database -BackupDirectory $BackupFolder -Type Full -CopyOnly -CompressBackup $EnableCompression -Checksum $EnableChecksum -Verify $EnableVerify -CreateFolder $CreateFolder
            Write-Host "Recovery model changed to Full and backup completed" -ForegroundColor Green
        }
        else {
            Write-Host "Database $database is already in Full recovery model" -ForegroundColor Green
        }
        
        # Check for existing mirroring on PRIMARY server
        $existingMirroring = Get-DbaDbMirror -SqlInstance $PrimaryServer -Database $database -ErrorAction SilentlyContinue
        
        if ($existingMirroring) {
            Write-Host "Removing existing mirroring for refresh..." -ForegroundColor Yellow
            Remove-DbaDbMirror -SqlInstance $PrimaryServer -Database $database -Confirm:$false
            Write-Host "Existing mirroring removed from primary server" -ForegroundColor Green
        }
        
        # Mirror server preparation - THIS IS THE UPDATED SECTION WITH FIXES
        $mirrorDb = Get-DbaDatabase -SqlInstance $MirrorServer -Database $database -ErrorAction SilentlyContinue
        $mirrorDbState = Get-DbaDbState -SqlInstance $MirrorServer -Database $database -ErrorAction SilentlyContinue
        
        # FIX 1: Check for and remove mirroring on MIRROR server first
        Write-Host "Checking for mirroring configuration on mirror server..." -ForegroundColor Yellow
        $mirrorSideMirroring = Get-DbaDbMirror -SqlInstance $MirrorServer -Database $database -ErrorAction SilentlyContinue
        
        if ($mirrorSideMirroring) {
            Write-Host "Removing mirroring configuration from mirror server..." -ForegroundColor Yellow
            try {
                Remove-DbaDbMirror -SqlInstance $MirrorServer -Database $database -Confirm:$false
                Write-Host "Successfully removed mirroring from mirror server" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not remove mirroring from mirror server using standard method: $_"
                # Fallback to direct T-SQL command
                try {
                    Invoke-DbaQuery -SqlInstance $MirrorServer -Database "master" -Query "ALTER DATABASE [$database] SET PARTNER OFF" -ErrorAction Stop
                    Write-Host "Successfully removed mirroring using T-SQL command" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not remove mirroring using T-SQL either: $_"
                }
            }
        }
        
        # FIX 2: Handle database in RESTORING state - RECOVER it first before trying to remove
        if ($mirrorDb -and $mirrorDbState.Status -eq "RESTORING") {
            Write-Host "Database $database is in RESTORING state on mirror server. Recovering..." -ForegroundColor Yellow
            try {
                Restore-DbaDatabase -SqlInstance $MirrorServer -DatabaseName $database -Recover
                Write-Host "Database recovered from RESTORING state" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not recover database using standard method: $_"
                # Try alternate method using T-SQL
                try {
                    $recoverSql = "RESTORE DATABASE [$database] WITH RECOVERY"
                    Invoke-DbaQuery -SqlInstance $MirrorServer -Query $recoverSql -Database "master"
                    Write-Host "Database recovered from RESTORING state using direct T-SQL" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not recover database using T-SQL either: $_"
                }
            }
        }
        
        # Now we can safely attempt to remove the database
        if ($mirrorDb) {
            Write-Host "Removing existing database $database from mirror server..." -ForegroundColor Yellow
            try {
                Remove-DbaDatabase -SqlInstance $MirrorServer -Database $database -Confirm:$false
                Write-Host "Existing database removed" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not remove existing database: $_"
                # Try alternate method using T-SQL
                try {
                    $dropSql = "DROP DATABASE [$database]"
                    Invoke-DbaQuery -SqlInstance $MirrorServer -Query $dropSql -Database "master"
                    Write-Host "Existing database removed using direct T-SQL" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not remove database using T-SQL either: $_"
                }
            }
        }
        
        # Check for and remove orphaned files
        Write-Host "Checking for orphaned database files on mirror server..." -ForegroundColor Yellow
        $orphanedFiles = Find-DbaOrphanedFile -SqlInstance $MirrorServer | 
            Where-Object {$_.FileName -like "*$database*" -or $_.RemoteFileName -like "*$database*"}
        
        if ($orphanedFiles) {
            Write-Host "Found $($orphanedFiles.Count) orphaned files related to database '$database'" -ForegroundColor Yellow
            
            foreach ($file in $orphanedFiles) {
                try {
                    Write-Host "Removing orphaned file: $($file.RemoteFileName)" -ForegroundColor Yellow
                    Remove-Item -Path $file.RemoteFileName -Force -ErrorAction Stop
                    Write-Host "Successfully removed: $($file.RemoteFileName)" -ForegroundColor Green
                } catch {
                    Write-Warning "Could not remove file: $($file.RemoteFileName). Error: $_"
                    # Try to release file locks
                    try {
                        # Get server name without instance
                        $serverName = $MirrorServer.Split('\')[0]
                        # Use administrative shares to access files
                        $adminPath = $file.RemoteFileName -replace ":", "$"
                        $adminPath = "\\$serverName\$adminPath"
                        Remove-Item -Path $adminPath -Force -ErrorAction Stop
                        Write-Host "Successfully removed file via admin share: $adminPath" -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Could not remove file via admin share either: $_"
                    }
                }
            }
        } else {
            Write-Host "No orphaned files found" -ForegroundColor Green
        }
        
        # Backup and Restore Process
        if (-not (Test-Path -Path $BackupFolder -IsValid)) {
            Write-Error "Backup folder path $BackupFolder is invalid or inaccessible"
            return $false
        }
        try {
            # Test by writing a small file
            $testFile = Join-Path -Path $BackupFolder -ChildPath "permtest_$([guid]::NewGuid()).txt"
            Set-Content -Path $testFile -Value "Testing permissions" -ErrorAction Stop
            Remove-Item -Path $testFile -Force
            Write-Host "Backup folder is accessible with proper permissions" -ForegroundColor Green
        } catch {
            Write-Error "SQL Server cannot write to the backup folder: $BackupFolder. Error: $_"
            return $false
        }
        
        # Create full backup with explicit path construction
        Write-Host "Creating full backup..." -ForegroundColor Yellow
        $fullBackupFile = "$database-Full-$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"
        $fullBackupPath = Join-Path -Path $BackupFolder -ChildPath $fullBackupFile
        
        $fullBackup = Backup-DbaDatabase -SqlInstance $PrimaryServer -Database $database -Path $BackupFolder -FilePath $fullBackupFile -Type Full -CopyOnly -CompressBackup:$EnableCompression -Checksum:$EnableChecksum -Verify:$EnableVerify -CreateFolder:$CreateFolder
        
        # Debug output to show paths
        Write-Host "Full backup file created as: $fullBackupFile" -ForegroundColor Cyan
        Write-Host "Full backup path: $fullBackupPath" -ForegroundColor Cyan
        Write-Host "Backup object Path property: $($fullBackup.Path)" -ForegroundColor Cyan
        
        if (-not $fullBackup) {
            Write-Error "Failed to create full backup for database $database"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Failed to create full backup"
            }
            continue
        }
        
        # Create log backup with explicit path construction
        Write-Host "Creating log backup..." -ForegroundColor Yellow
        $logBackupFile = "$database-Log-$(Get-Date -Format 'yyyyMMdd_HHmmss').trn"
        $logBackupPath = Join-Path -Path $BackupFolder -ChildPath $logBackupFile
        
        $logBackup = Backup-DbaDatabase -SqlInstance $PrimaryServer -Database $database -Path $BackupFolder -FilePath $logBackupFile -Type Log -CompressBackup:$EnableCompression -Checksum:$EnableChecksum -Verify:$EnableVerify -CreateFolder:$CreateFolder
        
        # Debug output to show paths
        Write-Host "Log backup file created as: $logBackupFile" -ForegroundColor Cyan
        Write-Host "Log backup path: $logBackupPath" -ForegroundColor Cyan
        Write-Host "Log backup object Path property: $($logBackup.Path)" -ForegroundColor Cyan
        
        if (-not $logBackup) {
            Write-Error "Failed to create log backup for database $database"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Failed to create log backup"
            }
            continue
        }
        
        # FIX 3: Double-check mirror server state before proceeding with restore
        Write-Host "Double-checking mirror server database state before restore..." -ForegroundColor Yellow
        $finalCheckDb = Get-DbaDatabase -SqlInstance $MirrorServer -Database $database -ErrorAction SilentlyContinue
        
        if ($finalCheckDb) {
            Write-Warning "Database still exists on mirror server. Attempting final forced removal..."
            try {
                # Force drop with ROLLBACK IMMEDIATE to terminate connections
                $dropForceSql = "IF EXISTS (SELECT 1 FROM sys.databases WHERE name = '$database')
                                 BEGIN
                                     ALTER DATABASE [$database] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                                     DROP DATABASE [$database];
                                 END"
                Invoke-DbaQuery -SqlInstance $MirrorServer -Database "master" -Query $dropForceSql
                Write-Host "Database forcefully removed" -ForegroundColor Green
            }
            catch {
                Write-Error "Cannot proceed with restore. Database still exists and cannot be removed: $_"
                $failureCount++
                $results += [PSCustomObject]@{
                    Database = $database
                    Status = "Failed" 
                    Message = "Cannot prepare mirror server - database cannot be removed"
                }
                continue
            }
        }
        
        # Restore full backup with NORECOVERY using explicit paths
        Write-Host "Restoring full backup on mirror with NORECOVERY..." -ForegroundColor Yellow
        $restoreFullParams = @{
            SqlInstance = $MirrorServer
            Path = $fullBackupPath  # Using explicit path instead of $fullBackup.Path
            DatabaseName = $database
            WithReplace = $true
            NoRecovery = $true
            MaxTransferSize = $MaxTransferSize
            BlockSize = $BlockSize
            BufferCount = $BufferCount
            UseDestinationDefaultDirectories = $true
        }

        if ($FileMapping -and $FileMapping.Count -gt 0) {
            $restoreFullParams.FileMapping = $FileMapping
        }

        try {
            # Add a brief pause to ensure SQL Server is ready
            Start-Sleep -Seconds 2
            
            # Perform the restore
            $restoreFullResult = Restore-DbaDatabase @restoreFullParams
            
            if (-not $restoreFullResult) {
                throw "Restore operation returned no results"
            }
            
            # Verify database state
            $dbState = Get-DbaDbState -SqlInstance $MirrorServer -Database $database -ErrorAction SilentlyContinue
            Write-Host "Database $database state after full restore: $($dbState.Status)" -ForegroundColor Green
            
            # Continue only if database is actually in RESTORING state
            if ($dbState.Status -ne "RESTORING") {
                throw "Database not properly in RESTORING state after full backup restore"
            }
        }
        catch {
            Write-Error "Failed to restore full backup on mirror server for database $database. Error: $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Failed to restore full backup on mirror: $_"
            }
            continue
        }

        # Restore log backup with NORECOVERY using explicit path
        Write-Host "Restoring log backup on mirror with NORECOVERY..." -ForegroundColor Yellow

        try {
            # Direct approach with explicit path
            $restoreLogResult = Restore-DbaDatabase -SqlInstance $MirrorServer -Path $logBackupPath -DatabaseName $database -NoRecovery -Continue -UseDestinationDefaultDirectories

            if (-not $restoreLogResult) {
                throw "Log restore operation returned no results"
            }
        }
        catch {
            Write-Error "Failed to restore log backup on mirror server for database $database. Error: $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Failed to restore log backup on mirror: $_"
            }
            continue
        }
       
        # Mirroring Setup
        Write-Host "Setting up database mirroring..." -ForegroundColor Cyan
                
        # Format endpoint URLs
        $primaryEndpointUrl = "TCP://${PrimaryServer}:${MIRRORING_PORT}"
        $mirrorEndpointUrl = "TCP://${MirrorServer}:${MIRRORING_PORT}"
        $witnessEndpointUrl = $null
        if ($WitnessServer) {
            $witnessEndpointUrl = "TCP://${WitnessServer}:${MIRRORING_PORT}"
        }
                
        # Set mirror partner on mirror server
        Write-Host "Setting up mirror partner on mirror server..." -ForegroundColor Yellow
        try {
            Set-DbaDbMirror -SqlInstance $MirrorServer -Database $database -Partner $primaryEndpointUrl -Confirm:$false
        }
        catch {
            Write-Error "Failed to set mirror partner on mirror server: $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Failed to set mirror partner: $_"
            }
            continue
        }
        
        # Set principal partner on primary server
        Write-Host "Setting up principal partner on primary server..." -ForegroundColor Yellow
        try {
            Set-DbaDbMirror -SqlInstance $PrimaryServer -Database $database -Partner $mirrorEndpointUrl -Confirm:$false
        }
        catch {
            Write-Error "Failed to set principal partner on primary server: $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Failed to set principal partner: $_"
            }
            continue
        }
        
        # Add witness if specified
        if ($WitnessServer -and $witnessEndpointUrl) {
            Write-Host "Setting up witness on primary server..." -ForegroundColor Yellow
            try {
                Set-DbaDbMirror -SqlInstance $PrimaryServer -Database $database -Witness $witnessEndpointUrl -Confirm:$false
            }
            catch {
                Write-Warning "Failed to set witness on primary server: $_"
                # Continue anyway as witness is optional
            }
        }
        
        # Set timeout value
        if ($MIRRORING_TIMEOUT -gt 0) {
            Write-Host "Setting mirroring timeout to $MIRRORING_TIMEOUT seconds..." -ForegroundColor Yellow
            try {
                $timeoutQuery = "ALTER DATABASE [$database] SET PARTNER TIMEOUT $MIRRORING_TIMEOUT;"
                Invoke-DbaQuery -SqlInstance $PrimaryServer -Database "master" -Query $timeoutQuery
            }
            catch {
                Write-Warning "Failed to set mirroring timeout: $_"
                # Continue anyway as timeout is optional
            }
        }
        
        # Handle orphaned users
        Write-Host "Handling orphaned users..." -ForegroundColor Yellow
        try {
            Handle-OrphanedUsers -ServerInstance $PrimaryServer -Database $database -Force
        }
        catch {
            Write-Warning "Failed to handle orphaned users: $_"
            # Continue anyway as orphaned users handling is optional
        }
        
        # Verify mirroring status
        try {
            $finalStatus = Get-DbaDbMirror -SqlInstance $PrimaryServer -Database $database
            
            if ($finalStatus) {
                Write-Host "Database '$database' mirroring status:" -ForegroundColor Cyan
                Write-Host "  - Role: Principal" -ForegroundColor Green
                Write-Host "  - Status: $($finalStatus.MirroringStatus)" -ForegroundColor Green
                Write-Host "  - Partner: $($finalStatus.MirroringPartner)" -ForegroundColor Green
                Write-Host "  - Safety Level: $($finalStatus.MirroringSafetyLevel)" -ForegroundColor Green
                Write-Host "  - Timeout: $($finalStatus.MirroringTimeout) seconds" -ForegroundColor Green
                
                if ($finalStatus.MirroringWitness) {
                    Write-Host "  - Witness: $($finalStatus.MirroringWitness)" -ForegroundColor Green
                }
                
                # Clean up backup files
                Write-Host "Cleaning up backup files..." -ForegroundColor Yellow
                Remove-MirroringBackupFiles -Database $database -BackupFolder $BackupFolder
                
                $successCount++
                $results += [PSCustomObject]@{
                    Database = $database
                    Status = "Success" 
                    Message = "Mirroring refreshed successfully"
                }
            }
            else {
                Write-Error "Failed to verify mirroring status for database $database"
                $failureCount++
                $results += [PSCustomObject]@{
                    Database = $database
                    Status = "Failed" 
                    Message = "Failed to verify mirroring status"
                }
            }
        }
        catch {
            Write-Error "Error checking mirroring status: $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $database
                Status = "Failed" 
                Message = "Error checking mirroring status: $_"
            }
        }
    }
    
    # Display summary
    Write-Host "`n=== Mirroring Refresh Summary ===" -ForegroundColor Cyan
    Write-Host "Total databases processed: $($databases.Count)" -ForegroundColor White
    Write-Host "Successfully refreshed: $successCount" -ForegroundColor Green
    Write-Host "Failed or skipped: $failureCount" -ForegroundColor Red
    
    # Display detailed results
    Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
    
    return ($successCount -gt 0)
}

function Remove-MirroringWithDbaTools {
    Write-Host "=== Removing Database Mirroring using dbatools ===" -ForegroundColor Cyan
    Write-Host "This operation removes mirroring while preserving databases" -ForegroundColor Yellow
    
    # Get the initial list of databases to process
    $allDatabases = Get-DatabaseList -ServerInstance $PRIMARY_SERVER -SpecifiedDatabases $DATABASE_LIST -ExcludedDatabases $EXCLUDED_DATABASES
    
    if (-not $allDatabases -or $allDatabases.Count -eq 0) {
        Write-Warning "No databases selected for processing."
        return
    }
    
    # Get all mirrored databases on the primary server
    $mirroredDatabases = Get-DbaDbMirror -SqlInstance $PRIMARY_SERVER | Select-Object -ExpandProperty Name
    
    # Filter to only databases that actually have mirroring
    $databasesToProcess = $allDatabases | Where-Object { $mirroredDatabases -contains $_ }
    
    # Report on databases found vs. databases with mirroring
    if ($databasesToProcess.Count -eq 0) {
        Write-Host "None of the selected databases have mirroring configured. Nothing to do." -ForegroundColor Yellow
        return
    }
    
    Write-Host "$($databasesToProcess.Count) of $($allDatabases.Count) selected databases have mirroring configured:" -ForegroundColor Cyan
    Write-Host "$($databasesToProcess -join ', ')" -ForegroundColor Yellow
    
    # Prompt for confirmation
    $confirmMessage = "Do you want to remove mirroring for these $($databasesToProcess.Count) databases? (Type 'y' for Yes or 'n' for No): "
    $confirmation = Read-Host $confirmMessage
    
    if ($confirmation.ToLower().Trim() -ne "y" -and $confirmation.ToLower().Trim() -ne "yes") {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        return
    }
    
    # Initialize tracking variables
    $successCount = 0
    $failureCount = 0
    $results = @()
    
    # Process all databases at once using dbatools
    try {
        Write-Host "Removing mirroring for selected databases..." -ForegroundColor Yellow
        
        # Get database objects and pipe directly to Remove-DbaDbMirror
        $dbObjects = Get-DbaDatabase -SqlInstance $PRIMARY_SERVER -Database $databasesToProcess -ExcludeSystem
        $removalResults = $dbObjects | Remove-DbaDbMirror -Confirm:$false
        
        # Process results
        foreach ($dbName in $databasesToProcess) {
            $result = $removalResults | Where-Object { $_.Database -eq $dbName }
            
            if ($result) {
                $successCount++
                $results += [PSCustomObject]@{
                    Database = $dbName
                    Status = "Success"
                    Message = "Mirroring removed successfully"
                }
                
                # Handle orphaned users on primary
                Write-Host "Handling orphaned users for $dbName on primary server..." -ForegroundColor Yellow
                try {
                    Handle-OrphanedUsers -ServerInstance $PRIMARY_SERVER -Database $dbName -Force
                    Write-Host "Orphaned users repaired for $dbName" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not repair orphaned users for $dbName : $_"
                }
            }
            else {
                $failureCount++
                $results += [PSCustomObject]@{
                    Database = $dbName
                    Status = "Failed"
                    Message = "Failed to remove mirroring"
                }
            }
        }
    }
    catch {
        Write-Error "Error removing mirroring: $_"
        $failureCount += $databasesToProcess.Count - $successCount
    }
    
    # Display summary
    Write-Host "`n=== Mirroring Removal Summary ===" -ForegroundColor Cyan
    Write-Host "Total mirrored databases processed: $($databasesToProcess.Count)" -ForegroundColor White
    Write-Host "Successfully removed: $successCount" -ForegroundColor Green
    Write-Host "Failed to remove: $failureCount" -ForegroundColor Red
    
    # Display detailed results if needed
    if ($failureCount -gt 0) {
        Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
        $results | Format-Table -AutoSize
    }
    
    Write-Host "Mirroring removal operation completed." -ForegroundColor Green
}

function Failover-MirroringWithDbaTools {
    Write-Host "=== Performing Database Mirroring Failover using dbatools ===" -ForegroundColor Cyan
    
    $databases = Get-DatabaseList -ServerInstance $PRIMARY_SERVER -SpecifiedDatabases $DATABASE_LIST -ExcludedDatabases $EXCLUDED_DATABASES
    
    if (-not $databases -or $databases.Count -eq 0) {
        Write-Warning "No databases selected for failover."
        return
    }
    
    # Verify PRIMARY_SERVER is actually principal for at least one database
    $isPrincipalForAny = $false
    foreach ($dbName in $databases) {
        # Use the correct command to check principal status
        $monitorStatus = Get-DbaDbMirrorMonitor -SqlInstance $PRIMARY_SERVER -Database $dbName -LimitResults LastRow -ErrorAction SilentlyContinue
        if ($monitorStatus -and $monitorStatus.Role -eq 1) {
            $isPrincipalForAny = $true
            break
        }
    }
    
    if (!$isPrincipalForAny) {
        Write-Warning "$PRIMARY_SERVER is not the principal for any selected databases."
        Write-Warning "It appears $MIRROR_SERVER is currently the principal. If you want to failover"
        Write-Warning "back to $PRIMARY_SERVER, swap the PRIMARY_SERVER and MIRROR_SERVER variables."
        return
    }
    
    Write-Host "Performing failover for databases: $($databases -join ', ')" -ForegroundColor Cyan
    
    # Always prompt once for failover even if FORCE_OPERATION is enabled
    if (-not $FORCE_OPERATION) {
        $confirmMessage = "Do you want to failover ALL selected databases ($($databases.Count) databases)? (Type 'y' for Yes or 'n' for No): "
    } else {
        $confirmMessage = "FORCE_OPERATION is enabled but we'll prompt once for safety. Failover ALL selected databases ($($databases.Count) databases)? (Type 'y' for Yes or 'n' for No): "
    }
    
    $confirmation = Read-Host $confirmMessage
    
    if ($confirmation.ToLower().Trim() -eq "y" -or $confirmation.ToLower().Trim() -eq "yes") {
        # Initialize success/failure tracking
        $successCount = 0
        $failureCount = 0
        $skippedCount = 0
        $results = @()
        
        foreach ($dbName in $databases) {
            Write-Host "Performing failover for database: $dbName" -ForegroundColor Yellow
            
            # Check if this database on PRIMARY_SERVER is the principal
            $monitorStatus = Get-DbaDbMirrorMonitor -SqlInstance $PRIMARY_SERVER -Database $dbName -LimitResults LastRow -ErrorAction SilentlyContinue
            
            if ($monitorStatus -and $monitorStatus.Role -eq 1) {
                try {
                    # Perform failover using Invoke-DbaDbMirrorFailover
                    Invoke-DbaDbMirrorFailover -SqlInstance $PRIMARY_SERVER -Database $dbName -Confirm:$false
                    
                    Write-Host "Successfully failed over database: $dbName" -ForegroundColor Green
                    $successCount++
                    $results += [PSCustomObject]@{
                        Database = $dbName
                        Status = "Success"
                        Message = "Failover completed successfully"
                        OriginalPrincipal = $PRIMARY_SERVER
                        NewPrincipal = $MIRROR_SERVER
                    }
                }
                catch {
                    Write-Error ("Error during failover for database $dbName`: " + $_)
                    $failureCount++
                    $results += [PSCustomObject]@{
                        Database = $dbName
                        Status = "Failed"
                        Message = $_.Exception.Message
                        OriginalPrincipal = $PRIMARY_SERVER
                        NewPrincipal = $PRIMARY_SERVER
                    }
                }
            } else {
                Write-Host "Database '$dbName' is not configured for mirroring or PRIMARY_SERVER is not the principal. Skipping." -ForegroundColor Yellow
                $skippedCount++
                $results += [PSCustomObject]@{
                    Database = $dbName
                    Status = "Skipped"
                    Message = "Database not mirrored or PRIMARY_SERVER not principal"
                    OriginalPrincipal = "Unknown"
                    NewPrincipal = "Unknown"
                }
            }
        }
        
        # Display summary
        Write-Host "`n=== Mirroring Failover Summary ===" -ForegroundColor Cyan
        Write-Host "Total databases processed: $($databases.Count)" -ForegroundColor White
        Write-Host "Successfully failed over: $successCount" -ForegroundColor Green
        Write-Host "Failed to failover: $failureCount" -ForegroundColor Red
        Write-Host "Skipped (not mirrored or PRIMARY_SERVER not principal): $skippedCount" -ForegroundColor Yellow
        
        # Display detailed results if needed
        if ($failureCount -gt 0 -or $skippedCount -gt 0) {
            Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
            $results | Format-Table -AutoSize
        }
        
        # Handle orphaned users for ALL databases after failover, regardless of FORCE_OPERATION setting
        if ($successCount -gt 0) {
            Write-Host "`n=== Repairing Orphaned Users on All Servers After Failover ===" -ForegroundColor Cyan
            
            foreach ($item in $results) {
                if ($item.Status -eq "Success") {
                    $dbName = $item.Database
                    
                    # After failover, the new principal is the MIRROR_SERVER
                    Write-Host "Repairing orphaned users for database '$dbName' on new principal server '$MIRROR_SERVER'..." -ForegroundColor Yellow
                    
                    try {
                        # Use the enhanced Handle-OrphanedUsers function with better reporting
                        $orphanRepairResult = Handle-OrphanedUsers -ServerInstance $MIRROR_SERVER -Database $dbName -Force -DetailedOutput -RemoveNotExisting
                        
                        if ($orphanRepairResult) {
                            Write-Host "Successfully repaired orphaned users for database '$dbName'" -ForegroundColor Green
                        } else {
                            Write-Host "Some orphaned users could not be fully repaired for database '$dbName'. Manual intervention may be required." -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Warning "Error handling orphaned users on new principal server for database '$dbName': $_"
                    }
                }
            }
        }
        
        Write-Host "Mirroring failover and orphaned user repair completed." -ForegroundColor Green
    } else {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        return
    }
}

function Emergency-RecoverMirroringDatabases {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SqlServer,
        
        [Parameter(Mandatory = $false)]
        [string[]]$DatabaseList = @()
    )
    
    $serverName = $SqlServer.Split('\')[0]
    
    Write-Host "=== EMERGENCY RECOVERY MODE ===" -ForegroundColor Red
    Write-Host "This mode will recover databases stuck in mirroring/restoring state" -ForegroundColor Red
    Write-Host "Server to recover: $SqlServer" -ForegroundColor Yellow
    
    # 1. Save current startup parameters
    Write-Host "Saving current SQL Server startup parameters..." -ForegroundColor Cyan
    $originalConfig = Get-DbaStartupParameter -SqlInstance $SqlServer
    
    # 2. Find and stop dependent services first
    Write-Host "Stopping dependent services..." -ForegroundColor Yellow
    $dependencies = sc.exe \\$serverName enumdepend MSSQLSERVER
    Write-Host $dependencies
    
    # 3. Stop SQL Server Agent first
    Write-Host "Stopping SQL Server Agent..." -ForegroundColor Yellow
    sc.exe \\$serverName stop SQLSERVERAGENT 
    Start-Sleep -Seconds 5
    
    # 4. Set startup parameter for single user mode with SQLCMD
    Write-Host "Setting SQL Server to start in Single User Mode with SQLCMD priority..." -ForegroundColor Yellow
    Set-DbaStartupParameter -SqlInstance $SqlServer -SingleUser -SingleUserDetails "SQLCMD" -Force
    
    # 5. Force stop SQL Server with proper timeout
    Write-Host "Stopping SQL Server forcefully..." -ForegroundColor Red
    $stopResult = sc.exe \\$serverName stop MSSQLSERVER
    Write-Host "Stop result: $stopResult"
    
    # 6. Wait for service to actually stop
    Write-Host "Waiting for SQL Server to fully stop..." -ForegroundColor Cyan
    $maxWait = 30
    $waited = 0
    do {
        Start-Sleep -Seconds 2
        $waited += 2
        $status = sc.exe \\$serverName query MSSQLSERVER
        Write-Host "." -NoNewline
    } while ($status -match "STOP_PENDING" -and $waited -lt $maxWait)
    Write-Host ""
    
    # 7. Start SQL Server
    Write-Host "Starting SQL Server in single user mode..." -ForegroundColor Green
    $startResult = sc.exe \\$serverName start MSSQLSERVER
    Write-Host "Start result: $startResult"
    Start-Sleep -Seconds 15  # Increased wait time
    
    # 8. If databaseList is "all", get all user databases using dbatools
    if ($DatabaseList -eq "all" -or $DatabaseList -contains "all" -or [string]::IsNullOrWhiteSpace($DatabaseList)) {
        Write-Host "Getting all user databases..." -ForegroundColor Yellow
        # Use sqlcmd since dbatools may open multiple connections
        $dbQuery = "SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0;"
        $dbResults = & sqlcmd -S $SqlServer -E -Q $dbQuery -h-1
    
        # Properly filter results to exclude the "rows affected" message
        $DatabaseList = $dbResults | Where-Object { 
            $_ -match '\S' -and 
            $_ -notmatch '^-+$' -and 
            $_ -notmatch 'name' -and 
            $_ -notmatch 'rows affected'
        }
    
        Write-Host "Found $($DatabaseList.Count) user databases:" -ForegroundColor Green
        Write-Host ($DatabaseList -join ", ") -ForegroundColor Green
    }
    
    # 9. Turn off mirroring for each database - UPDATED to always show status
    # Using direct sqlcmd commands for emergency recovery as they work reliably in single-user mode
   
    Write-Host "Turning off mirroring for databases..." -ForegroundColor Green
    foreach($db in $DatabaseList) {
        $db = $db.Trim() # Remove any whitespace
        Write-Host "Processing database [$db]..." -ForegroundColor Yellow
    
        # Execute with improved error handling and status messages
        $result = & sqlcmd -S $SqlServer -E -Q "
        BEGIN TRY
            -- Check if mirroring is configured
            IF EXISTS (SELECT 1 FROM sys.database_mirroring WHERE database_id = DB_ID('$db') AND mirroring_guid IS NOT NULL)
            BEGIN
                ALTER DATABASE [$db] SET PARTNER OFF;
                PRINT 'Successfully disabled mirroring for $db';
            END
            ELSE
            BEGIN
                PRINT 'Mirroring not configured for $db - no action needed';
            END
        END TRY
        BEGIN CATCH
            PRINT 'Error processing $db : ' + ERROR_MESSAGE();
        END CATCH;" -b
    
        # Display all messages for better feedback
        if ($result) {
            foreach ($line in $result) {
                if ($line -match "Successfully") {
                    Write-Host $line -ForegroundColor Green
                } 
                elseif ($line -match "not configured") {
                    Write-Host $line -ForegroundColor Cyan
                }
                elseif ($line -match "Error") {
                    Write-Host $line -ForegroundColor Red
                }
            }
        }
    }
    
    # 10. Restore original startup parameters with retry logic
    Write-Host "Restoring original SQL Server startup parameters..." -ForegroundColor Yellow
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            # Suppress warnings by redirecting them
            $warningPreference = 'SilentlyContinue'
            Set-DbaStartupParameter -SqlInstance $SqlServer -StartupConfig $originalConfig -Force -WarningAction SilentlyContinue
            $success = $true
            Write-Host "Successfully restored startup parameters" -ForegroundColor Green
        }
        catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Write-Host "Failed to restore startup parameters. Retrying in 5 seconds... (Attempt $retryCount of $maxRetries)" -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
            else {
                Write-Host "Warning: Could not restore startup parameters properly. Continuing with script." -ForegroundColor Yellow
            }
        }
        finally {
            # Reset warning preference
            $warningPreference = 'Continue'
        }
    }
    
    # 11. Restart SQL Server normally
    Write-Host "Stopping SQL Server..." -ForegroundColor Cyan
    sc.exe \\$serverName stop MSSQLSERVER
    Start-Sleep -Seconds 10  # Increased wait time
    
    Write-Host "Starting SQL Server normally..." -ForegroundColor Cyan
    sc.exe \\$serverName start MSSQLSERVER
    Start-Sleep -Seconds 20  # Increased wait time for full startup
    
    # 12. Start SQL Server Agent
    Write-Host "Starting SQL Server Agent..." -ForegroundColor Yellow  
    sc.exe \\$serverName start SQLSERVERAGENT
    Start-Sleep -Seconds 5
    
    # 13. Connect to SQL Server to perform database operations
    Write-Host "Connecting to SQL Server..." -ForegroundColor Cyan
    $conn = Connect-DbaInstance -SqlInstance $SqlServer
    
    # 14. Restore databases with RECOVERY using dbatools
    if ($DatabaseList -ne "all" -or (Read-Host "Do you want to run RESTORE WITH RECOVERY on all databases? (Type 'y' for Yes or 'n' for No): ").ToLower().Trim() -eq "y") {
        Write-Host "Restoring databases with RECOVERY..." -ForegroundColor Green
        foreach($db in $DatabaseList) {
            $db = $db.Trim() # Remove any whitespace
            Write-Host "Recovering database [$db]..." -ForegroundColor Yellow
    
            try {
                # Check if database needs recovery
                $dbState = Get-DbaDatabase -SqlInstance $conn -Database $db
                if ($dbState.Status -ne "Normal") {
                    # Restore with RECOVERY
                    Restore-DbaDatabase -SqlInstance $conn -DatabaseName $db -RecoveryMode Recover -ErrorAction Stop
                    Write-Host "Successfully recovered $db" -ForegroundColor Green
                } else {
                    Write-Host "Database $db is already in normal state - no recovery needed" -ForegroundColor Cyan
                }
    
                # Check if database needs multi-user mode
                if ($dbState.Status -match "Single") {
                    # Set MULTI_USER
                    Set-DbaDbState -SqlInstance $conn -Database $db -MultiUser -ErrorAction Stop
                    Write-Host "Successfully set $db to MULTIUSER mode" -ForegroundColor Green
                } else {
                    Write-Host "Database $db is already in multi-user mode" -ForegroundColor Cyan
                }
            }
            catch {
                # Filter out already recovered messages
                if ($_.Exception.Message -match "already fully recovered") {
                    Write-Host "Database $db is already recovered." -ForegroundColor Cyan
                } else {
                    Write-Host "Error: $_" -ForegroundColor Red
                }
            }
        }
    }
    
    # 15. Verify database states using dbatools
    Write-Host "Verifying database states..." -ForegroundColor Cyan
    $dbStates = Get-DbaDatabase -SqlInstance $conn | 
                Where-Object {$DatabaseList -contains $_.Name -or $DatabaseList -contains "all" -or [string]::IsNullOrWhiteSpace($DatabaseList)} |
                Select-Object Name, Status, RecoveryModel, Owner, IsAccessible, LastFullBackup
    $dbStates | Format-Table -AutoSize
    
    # Disconnect
    Disconnect-DbaInstance -SqlInstance $conn
    
    Write-Host "Emergency recovery completed. Databases should now be operational." -ForegroundColor Green
    Write-Host "Please check the status report above to verify all databases were successfully recovered." -ForegroundColor Yellow
}

function Add-MirroringWitness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SqlInstance = $PRIMARY_SERVER,
        
        [Parameter(Mandatory = $false)]
        [string]$WitnessServer = $WITNESS_SERVER,
        
        [Parameter(Mandatory = $false)]
        [string]$DatabaseList = $DATABASE_LIST,
        
        [Parameter(Mandatory = $false)]
        [string]$ExcludedDatabases = $EXCLUDED_DATABASES,
        
        [Parameter(Mandatory = $false)]
        [int]$MirroringPort = $MIRRORING_PORT,
        
        [Parameter(Mandatory = $false)]
        [string]$EndpointName = $ENDPOINT_NAME,
        
        [Parameter(Mandatory = $false)]
        [string]$Encryption = $ENDPOINT_ENCRYPTION,
        
        [Parameter(Mandatory = $false)]
        [string]$Algorithm = $ENCRYPTION_ALGORITHM,
        
        [Parameter(Mandatory = $false)]
        [switch]$Confirm = (-not $FORCE_OPERATION)
    )
    
    Write-Host "=== Adding Database Mirroring Witness ===" -ForegroundColor Cyan
    
    # Validate witness server is specified
    if ([string]::IsNullOrWhiteSpace($WitnessServer)) {
        Write-Error "WITNESS_SERVER parameter must be specified for ADD_WITNESS mode."
        return $false
    }
    
    # Get initial database list to process using the standard function
    $allDatabases = Get-DatabaseList -ServerInstance $SqlInstance -SpecifiedDatabases $DatabaseList -ExcludedDatabases $ExcludedDatabases
    
    if (-not $allDatabases -or $allDatabases.Count -eq 0) {
        Write-Warning "No databases selected for adding witness. Please check your DATABASE_LIST and EXCLUDED_DATABASES settings."
        return $false
    }
    
    # ENHANCEMENT: Filter the list to only include databases that are actually mirrored
    $mirroredDbInfo = Get-DbaDbMirror -SqlInstance $SqlInstance -ErrorAction SilentlyContinue
    if ($mirroredDbInfo) {
        $mirroredDatabases = $mirroredDbInfo | Select-Object -ExpandProperty Name
        $databases = $allDatabases | Where-Object { $mirroredDatabases -contains $_ }
        
        if ($databases.Count -eq 0) {
            Write-Warning "None of the selected databases have mirroring configured. Nothing to do."
            return $false
        }
        
        Write-Host "Found $($databases.Count) mirrored databases from selection: $($databases -join ', ')" -ForegroundColor Green
    } else {
        Write-Warning "No mirrored databases found on $SqlInstance."
        return $false
    }
    
    Write-Host "Adding witness $WitnessServer to mirroring for databases: $($databases -join ', ')" -ForegroundColor Cyan
    
    if ($Confirm) {
        $confirmResponse = Read-Host "Do you want to add the witness server to these databases? (y/n)"
        if ($confirmResponse.ToLower().Trim() -ne "y" -and $confirmResponse.ToLower().Trim() -ne "yes") {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return $false
        }
    }
    
    # Initialize counters
    $successCount = 0
    $failureCount = 0
    $skippedCount = 0
    $results = @()
    
    # Create endpoint on witness server if it doesn't exist
    Write-Host "Setting up endpoint on witness server..." -ForegroundColor Yellow
    $witnessEndpoint = Get-DbaEndpoint -SqlInstance $WitnessServer | 
        Where-Object { $_.EndpointType -eq "DatabaseMirroring" }
            
    if ($witnessEndpoint) {
        Write-Host "Using existing mirroring endpoint: $($witnessEndpoint.Name) on witness server" -ForegroundColor Yellow
    }
    else {
        Write-Host "Creating new mirroring endpoint on witness server using T-SQL..." -ForegroundColor Yellow
        try {
            # Format the encryption setting
            $encryptionSetting = switch ($Encryption.ToUpper()) {
                "REQUIRED" { "REQUIRED" }
                "SUPPORTED" { "SUPPORTED" }
                "DISABLED" { "DISABLED" }
                default { "REQUIRED" }
            }
            
            # Format the algorithm setting
            $algorithmSetting = if ($encryptionSetting -eq "DISABLED") {
                ""
            } else {
                "ALGORITHM $Algorithm"
            }

            # Create the T-SQL command for endpoint creation with WITNESS role
            $createEndpointSql = @"
CREATE ENDPOINT [$EndpointName]
STATE = STARTED
AS TCP (LISTENER_PORT = $MirroringPort, LISTENER_IP = ALL)
FOR DATA_MIRRORING (ROLE = WITNESS, AUTHENTICATION = WINDOWS NEGOTIATE, ENCRYPTION = $encryptionSetting $algorithmSetting)
"@
            
            # Execute the T-SQL command
            Invoke-DbaQuery -SqlInstance $WitnessServer -Query $createEndpointSql -ErrorAction Stop
            Write-Host "Successfully created new endpoint '$EndpointName' with role 'WITNESS' using T-SQL" -ForegroundColor Green
            Write-Host "T-SQL used: $createEndpointSql" -ForegroundColor Gray
            
            # Get the new endpoint for further operations
            $witnessEndpoint = Get-DbaEndpoint -SqlInstance $WitnessServer -Type DatabaseMirroring -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to create endpoint on witness server: $_"
            return $false
        }
    }
    
    # Verify endpoint is started without restarting SQL service
    try {
        $endpoint = Get-DbaEndpoint -SqlInstance $WitnessServer -Type DatabaseMirroring
        if ($endpoint.State -ne "Started") {
            Write-Host "Starting witness endpoint manually..." -ForegroundColor Yellow
            Start-DbaEndpoint -SqlInstance $WitnessServer -Endpoint $EndpointName
        }
        Write-Host "Confirmed endpoint is started" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not verify endpoint state: $_"
    }
    
    # Set endpoint owner on witness
    $witnessServiceAccount = Get-SqlServiceAccount -ServerInstance $WitnessServer
    Write-Host "SQL Service Account for ${WitnessServer}: $witnessServiceAccount" -ForegroundColor Green
    
    # Ensure service account exists as login
    Ensure-ServiceAccountLogin -SqlInstance $WitnessServer -ServiceAccount $witnessServiceAccount
    
    # Set endpoint owner
    Write-Host "Setting endpoint owner to $witnessServiceAccount on witness server..." -ForegroundColor Yellow
    Set-DbaEndpoint -SqlInstance $WitnessServer -Endpoint $EndpointName -Owner $witnessServiceAccount
    Write-Host "Endpoint owner set to $witnessServiceAccount" -ForegroundColor Green
    
    # Start endpoint
    Write-Host "Starting witness endpoint..." -ForegroundColor Yellow
    Start-DbaEndpoint -SqlInstance $WitnessServer -Endpoint $EndpointName
    
    # Set up endpoint permissions
    Write-Host "Setting up endpoint permissions..." -ForegroundColor Yellow
    Setup-EndpointPermissions -PrimaryServer $SqlInstance -MirrorServer $MIRROR_SERVER -WitnessServer $WitnessServer
    
    # IMPORTANT: Restart SQL Server on witness BEFORE adding the witness
    Write-Host "Restarting SQL Server service on witness server to initialize endpoint..." -ForegroundColor Yellow
    $witnessComputerName = $WitnessServer.Split('\')[0]
    
    # Stop SQL Server service
    Write-Host "Stopping SQL Server service on $witnessComputerName..." -ForegroundColor Yellow
    $stopResult = sc.exe \\$witnessComputerName stop MSSQLSERVER
    Write-Host "Stop result: $stopResult"
    
    # Wait for service to fully stop using dynamic check
    Write-Host "Waiting for SQL Server service to fully stop..." -ForegroundColor Yellow
    $maxWaitStop = 30
    $waitedStop = 0
    do {
        Start-Sleep -Seconds 2
        $waitedStop += 2
        $status = sc.exe \\$witnessComputerName query MSSQLSERVER
        Write-Host "." -NoNewline
    } while ($status -match "STOP_PENDING" -and $waitedStop -lt $maxWaitStop)
    Write-Host ""
    
    # Start SQL Server service
    Write-Host "Starting SQL Server service on $witnessComputerName..." -ForegroundColor Yellow
    $startResult = sc.exe \\$witnessComputerName start MSSQLSERVER
    Write-Host "Start result: $startResult"
    
    # Wait for SQL Server to fully initialize using dynamic check
    Write-Host "Waiting for SQL Server to fully initialize..." -ForegroundColor Yellow
    $maxWaitStart = 60
    $waitedStart = 0
    $connected = $false
    
    do {
        Start-Sleep -Seconds 2
        $waitedStart += 2
        Write-Host "." -NoNewline
        
        try {
            # Try to connect to the restarted instance
            $conn = Connect-DbaInstance -SqlInstance $WitnessServer -ConnectTimeout 2 -ErrorAction Stop
            $connected = $true
            Disconnect-DbaInstance -SqlInstance $conn
            Write-Host "`nSuccessfully connected to restarted witness server" -ForegroundColor Green
            break
        }
        catch {
            # Keep waiting until timeout
        }
    } while ($waitedStart -lt $maxWaitStart)
    
    if (-not $connected) {
        Write-Warning "Could not verify connection to witness server after $maxWaitStart seconds. Continuing anyway..."
    }
    
    # Format the witness endpoint URL
    $witnessEndpointUrl = "TCP://${WitnessServer}:${MirroringPort}"
    
    # Add witness to each mirrored database
    foreach ($dbName in $databases) {
        Write-Host "Adding witness for database: $dbName" -ForegroundColor Yellow
        
        try {
            # Use Get-DbaDbMirrorMonitor to determine roles more reliably
            $primaryMonitor = Get-DbaDbMirrorMonitor -SqlInstance $SqlInstance -Database $dbName -LimitResults LastRow -ErrorAction SilentlyContinue
            $mirrorMonitor = Get-DbaDbMirrorMonitor -SqlInstance $MIRROR_SERVER -Database $dbName -LimitResults LastRow -ErrorAction SilentlyContinue
            
            # Find principal server (Role = 1 is Principal, Role = 2 is Mirror)
            $principalServer = $null
            if ($primaryMonitor -and $primaryMonitor.Role -eq 1) {
                $principalServer = $SqlInstance
                Write-Host "Found principal role on $SqlInstance for database $dbName" -ForegroundColor Green
            }
            elseif ($mirrorMonitor -and $mirrorMonitor.Role -eq 1) {
                $principalServer = $MIRROR_SERVER
                Write-Host "Found principal role on $MIRROR_SERVER for database $dbName" -ForegroundColor Green
            }
            
            if ($principalServer) {
                # Check if witness is already configured
                $mirrorStatusBefore = Get-DbaDbMirror -SqlInstance $principalServer -Database $dbName
                if ($mirrorStatusBefore -and -not [string]::IsNullOrWhiteSpace($mirrorStatusBefore.MirroringWitness)) {
                    Write-Host "Database $dbName already has witness configured: $($mirrorStatusBefore.MirroringWitness)" -ForegroundColor Yellow
                    $skippedCount++
                    $results += [PSCustomObject]@{
                        Database = $dbName
                        Status = "Skipped"
                        Principal = $principalServer
                        Message = "Witness already configured"
                    }
                } else {
                    # Add witness to the principal server
                    $null = Set-DbaDbMirror -SqlInstance $principalServer -Database $dbName -Witness $witnessEndpointUrl -Confirm:$false
                    
                    # VERIFY if witness was actually added and connected
                    Start-Sleep -Seconds 3
                    $mirrorStatusAfter = Get-DbaDbMirror -SqlInstance $principalServer -Database $dbName
                    
                    if ($mirrorStatusAfter -and 
                        -not [string]::IsNullOrWhiteSpace($mirrorStatusAfter.MirroringWitness) -and 
                        $mirrorStatusAfter.MirroringWitnessStatus -eq "Connected") {
                        
                        Write-Host "Successfully added witness for database $dbName" -ForegroundColor Green
                        $successCount++
                        $results += [PSCustomObject]@{
                            Database = $dbName
                            Status = "Success"
                            Principal = $principalServer
                            Message = "Witness added successfully"
                        }
                    } else {
                        Write-Host "Failed to add witness for database $dbName - Witness not properly connected" -ForegroundColor Red
                        $failureCount++
                        $results += [PSCustomObject]@{
                            Database = $dbName
                            Status = "Failed"
                            Principal = $principalServer
                            Message = "Witness added but not properly connected"
                        }
                    }
                }
            }
            else {
                # Check if database has mirroring at all (should be redundant with our initial filtering)
                $hasMirroring = ($primaryMonitor -or $mirrorMonitor) -or 
                               (Get-DbaDbMirror -SqlInstance $SqlInstance -Database $dbName) -or
                               (Get-DbaDbMirror -SqlInstance $MIRROR_SERVER -Database $dbName)
                
                if ($hasMirroring) {
                    Write-Warning "Database $dbName has mirroring configured but could not determine principal. Skipping."
                    $failureCount++
                    $results += [PSCustomObject]@{
                        Database = $dbName
                        Status = "Failed"
                        Principal = "Unknown"
                        Message = "Could not determine principal server"
                    }
                } else {
                    Write-Warning "Database $dbName does not have mirroring configured. Skipping."
                    $failureCount++
                    $results += [PSCustomObject]@{
                        Database = $dbName
                        Status = "Skipped"
                        Principal = "N/A"
                        Message = "Mirroring not configured"
                    }
                }
            }
        }
        catch {
            Write-Error "Failed to add witness for database $dbName : $_"
            $failureCount++
            $results += [PSCustomObject]@{
                Database = $dbName
                Status = "Failed"
                Principal = "Unknown"
                Message = $_.Exception.Message
            }
        }
    }
    
    # Display summary
    Write-Host "`n=== Witness Addition Summary ===" -ForegroundColor Cyan
    Write-Host "Total databases processed: $($databases.Count)" -ForegroundColor White
    Write-Host "Successfully added witness: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failureCount" -ForegroundColor Red
    Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
    
    # Display detailed results
    Write-Host "`n=== Detailed Results ===" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
    
    return ($failureCount -eq 0)
}

function Extract-MirroringConfig {
    Write-Host "=== Extracting Database Mirroring Configuration ===" -ForegroundColor Cyan
    
    if ([string]::IsNullOrWhiteSpace($PRIMARY_SERVER)) {
        Write-Error "Primary server must be specified for extraction."
        return
    }
    
    try {
        # Connect to primary server
        try {
            $testConnection = Connect-DbaInstance -SqlInstance $PRIMARY_SERVER -ErrorAction Stop
            Write-Host "Successfully connected to $PRIMARY_SERVER" -ForegroundColor Green
        }
        catch {
            Write-Error "Authentication failed for $PRIMARY_SERVER. Check credentials and ensure server is available."
            return
        }
        
        # Get mirroring information
        $mirrorResults = Get-DbaDbMirror -SqlInstance $PRIMARY_SERVER -ErrorAction SilentlyContinue
        
        # Extract mirror and witness servers, timeout, and mirrored databases
        $detectedMirrorServer = $null
        $detectedWitnessServer = $null
        $mirrorTimeout = $null
        $mirroredDatabaseNames = @()
        
        foreach ($mirror in $mirrorResults) {
            $mirroredDatabaseNames += $mirror.Name
            
            # Get timeout from mirroring info
            if ($null -eq $mirrorTimeout -and $mirror.MirroringTimeout -gt 0) {
                $mirrorTimeout = $mirror.MirroringTimeout
            }
            
            # Extract mirror server
            if ([string]::IsNullOrEmpty($detectedMirrorServer) -and $mirror.MirroringPartner -match "TCP://(.*?):\d+") {
                $detectedMirrorServer = $matches[1]
            }
            
            # Extract witness server
            if ([string]::IsNullOrEmpty($detectedWitnessServer) -and $mirror.MirroringWitness -match "TCP://(.*?):\d+") {
                $detectedWitnessServer = $matches[1]
            }
        }
        
        # Set default timeout if not found
        if ($null -eq $mirrorTimeout) {
            $mirrorTimeout = 30
        }
        
        # Get endpoint information using dbatools first
        $primaryEndpoint = Get-DbaEndpoint -SqlInstance $PRIMARY_SERVER -Type DatabaseMirroring | Select-Object -First 1
        Write-Host "Primary endpoint found: $($primaryEndpoint.Name), Port: $($primaryEndpoint.Port)" -ForegroundColor Cyan
        
        # Define the correct endpoint encryption query
        $endpointQuery = @"
USE master;
SELECT 
    name AS EndpointName,
    type_desc AS EndpointType,
    state_desc AS EndpointState,
    role_desc AS RoleType,
    is_encryption_enabled AS EncryptionEnabled,
    encryption_algorithm_desc AS EncryptionAlgorithm,
    CASE 
        WHEN is_encryption_enabled = 1 THEN 'Required'
        WHEN is_encryption_enabled = 0 AND encryption_algorithm_desc = 'NONE' THEN 'Disabled'
        WHEN is_encryption_enabled = 0 AND encryption_algorithm_desc != 'NONE' THEN 'Supported'
    END AS EncryptionStatus
FROM sys.database_mirroring_endpoints
WHERE type = 4; -- DATABASE_MIRRORING
"@
        
        # Query primary server for endpoint encryption settings
        Write-Host "Querying endpoint encryption settings from primary server..." -ForegroundColor Cyan
        $primaryQueryResult = Invoke-DbaQuery -SqlInstance $PRIMARY_SERVER -Query $endpointQuery
        
        Write-Host "Raw query results for primary server:" -ForegroundColor Yellow
        $primaryQueryResult | Format-Table
        
        # Access query results directly
        $primaryEndpointName = ""
        $primaryPort = ""
        $primaryEncryption = ""
        $primaryAlgorithm = ""
        
        # Process the results row by row to avoid indexing issues
        foreach ($row in $primaryQueryResult) {
            $primaryEndpointName = $row.EndpointName
            $primaryPort = $primaryEndpoint.Port
            $primaryEncryption = $row.EncryptionStatus
            $primaryAlgorithm = $row.EncryptionAlgorithm
            
            Write-Host "Primary endpoint encryption details:" -ForegroundColor Green
            Write-Host "  Name: $primaryEndpointName" -ForegroundColor Green
            Write-Host "  Port: $primaryPort" -ForegroundColor Green
            Write-Host "  Encryption: $primaryEncryption" -ForegroundColor Green
            Write-Host "  Algorithm: $primaryAlgorithm" -ForegroundColor Green
            break
        }
        
        # Query mirror server if available
        $mirrorEndpointName = ""
        $mirrorPort = ""
        $mirrorEncryption = ""
        $mirrorAlgorithm = ""
        
        if (-not [string]::IsNullOrEmpty($detectedMirrorServer)) {
            Write-Host "Querying endpoint encryption settings from mirror server..." -ForegroundColor Cyan
            $mirrorQueryResult = Invoke-DbaQuery -SqlInstance $detectedMirrorServer -Query $endpointQuery
            
            Write-Host "Raw query results for mirror server:" -ForegroundColor Yellow
            $mirrorQueryResult | Format-Table
            
            # Process the results row by row
            foreach ($row in $mirrorQueryResult) {
                $mirrorEndpoint = Get-DbaEndpoint -SqlInstance $detectedMirrorServer -Type DatabaseMirroring | Select-Object -First 1
                $mirrorEndpointName = $row.EndpointName
                $mirrorPort = $mirrorEndpoint.Port
                $mirrorEncryption = $row.EncryptionStatus
                $mirrorAlgorithm = $row.EncryptionAlgorithm
                
                Write-Host "Mirror endpoint encryption details:" -ForegroundColor Green
                Write-Host "  Name: $mirrorEndpointName" -ForegroundColor Green
                Write-Host "  Port: $mirrorPort" -ForegroundColor Green
                Write-Host "  Encryption: $mirrorEncryption" -ForegroundColor Green
                Write-Host "  Algorithm: $mirrorAlgorithm" -ForegroundColor Green
                break
            }
        }
        
        # Query witness server if available
        $witnessEndpointName = ""
        $witnessPort = ""
        $witnessEncryption = ""
        $witnessAlgorithm = ""
        
        if (-not [string]::IsNullOrEmpty($detectedWitnessServer)) {
            Write-Host "Querying endpoint encryption settings from witness server..." -ForegroundColor Cyan
            $witnessQueryResult = Invoke-DbaQuery -SqlInstance $detectedWitnessServer -Query $endpointQuery
            
            Write-Host "Raw query results for witness server:" -ForegroundColor Yellow
            $witnessQueryResult | Format-Table
            
            # Process the results row by row
            foreach ($row in $witnessQueryResult) {
                $witnessEndpoint = Get-DbaEndpoint -SqlInstance $detectedWitnessServer -Type DatabaseMirroring | Select-Object -First 1
                $witnessEndpointName = $row.EndpointName
                $witnessPort = $witnessEndpoint.Port
                $witnessEncryption = $row.EncryptionStatus
                $witnessAlgorithm = $row.EncryptionAlgorithm
                
                Write-Host "Witness endpoint encryption details:" -ForegroundColor Green
                Write-Host "  Name: $witnessEndpointName" -ForegroundColor Green
                Write-Host "  Port: $witnessPort" -ForegroundColor Green
                Write-Host "  Encryption: $witnessEncryption" -ForegroundColor Green
                Write-Host "  Algorithm: $witnessAlgorithm" -ForegroundColor Green
                break
            }
        }
        
        # Compare encryption settings between servers
        $encryptionMismatch = $false
        $algorithmMismatch = $false
        
        Write-Host "Comparing endpoint encryption settings between servers..." -ForegroundColor Cyan
        
        # Compare primary with mirror if mirror info available
        if (-not [string]::IsNullOrEmpty($mirrorEncryption)) {
            if ($primaryEncryption -ne $mirrorEncryption) {
                $encryptionMismatch = $true
                Write-Host "WARNING: Encryption setting differs between primary and mirror:" -ForegroundColor Red
                Write-Host "  Primary: $primaryEncryption" -ForegroundColor Red
                Write-Host "  Mirror: $mirrorEncryption" -ForegroundColor Red
            }
            
            if ($primaryAlgorithm -ne $mirrorAlgorithm) {
                $algorithmMismatch = $true
                Write-Host "WARNING: Encryption algorithm differs between primary and mirror:" -ForegroundColor Red
                Write-Host "  Primary: $primaryAlgorithm" -ForegroundColor Red
                Write-Host "  Mirror: $mirrorAlgorithm" -ForegroundColor Red
            }
        }
        
        # Compare primary with witness if witness info available
        if (-not [string]::IsNullOrEmpty($witnessEncryption)) {
            if ($primaryEncryption -ne $witnessEncryption) {
                $encryptionMismatch = $true
                Write-Host "WARNING: Encryption setting differs between primary and witness:" -ForegroundColor Red
                Write-Host "  Primary: $primaryEncryption" -ForegroundColor Red
                Write-Host "  Witness: $witnessEncryption" -ForegroundColor Red
            }
            
            if ($primaryAlgorithm -ne $witnessAlgorithm) {
                $algorithmMismatch = $true
                Write-Host "WARNING: Encryption algorithm differs between primary and witness:" -ForegroundColor Red
                Write-Host "  Primary: $primaryAlgorithm" -ForegroundColor Red
                Write-Host "  Witness: $witnessAlgorithm" -ForegroundColor Red
            }
        }
        
        # If no discrepancies, confirm consistency
        if (-not $encryptionMismatch -and -not $algorithmMismatch -and (-not [string]::IsNullOrEmpty($primaryEncryption))) {
            Write-Host "Endpoint encryption settings are consistent across all servers." -ForegroundColor Green
        }
        
        # Get databases for exclusion list
        $allDatabases = Get-DbaDatabase -SqlInstance $PRIMARY_SERVER
        $systemDbs = $allDatabases | Where-Object { $_.IsSystemObject -eq $true } | Select-Object -ExpandProperty Name
        $userDbs = $allDatabases | Where-Object { $_.IsSystemObject -eq $false } | Select-Object -ExpandProperty Name
        $nonMirroredDbs = $userDbs | Where-Object { $mirroredDatabaseNames -notcontains $_ }
        $excludedDbs = $systemDbs + $nonMirroredDbs
        
        # Create configuration output
        $outputContent = ""
        $outputContent += "# SERVER INFORMATION" + [Environment]::NewLine
        $outputContent += '$PRIMARY_SERVER = "' + $PRIMARY_SERVER + '"   # Primary server name with FQDN' + [Environment]::NewLine
        $outputContent += '$MIRROR_SERVER = "' + $detectedMirrorServer + '"    # Mirror server name with FQDN' + [Environment]::NewLine
        $outputContent += '$WITNESS_SERVER = "' + $detectedWitnessServer + '"     # Witness server name with FQDN (leave empty if no witness)' + [Environment]::NewLine
        
        $outputContent += [Environment]::NewLine + '# DATABASE SETTINGS' + [Environment]::NewLine
        $outputContent += '# Database list options:' + [Environment]::NewLine
        $outputContent += '# 1. Single database: "db1"' + [Environment]::NewLine
        $outputContent += '# 2. Multiple specific databases: "db1,db2,db3" (comma-separated, no spaces)' + [Environment]::NewLine
        $outputContent += '# 3. All user databases that have mirroring: use an empty string "" or the string "ALL"' + [Environment]::NewLine
        $outputContent += '# NOTE: When using existing backups, ensure backup files are named: DatabaseName.bak' + [Environment]::NewLine
        
        $outputContent += '$DATABASE_LIST = "' + ($mirroredDatabaseNames -join ',') + '"  ' + [Environment]::NewLine
        
        $outputContent += [Environment]::NewLine + '# Databases to exclude from processing (always applied, even when using "ALL")' + [Environment]::NewLine
        $outputContent += '# System databases (master, model, msdb, tempdb) are always excluded automatically' + [Environment]::NewLine
        $outputContent += '$EXCLUDED_DATABASES = "' + ($excludedDbs -join ',') + '"' + [Environment]::NewLine
        
        $outputContent += [Environment]::NewLine + '# MIRRORING SETTINGS' + [Environment]::NewLine
        $outputContent += '$MIRRORING_PORT = ' + $primaryPort + '  # Mirroring port' + [Environment]::NewLine
        
        if ($encryptionMismatch) {
            $outputContent += '# WARNING: Encryption setting discrepancy detected between servers' + [Environment]::NewLine
            $finalEncryption = ""
        } else {
            $finalEncryption = $primaryEncryption
        }
        $outputContent += '$ENDPOINT_ENCRYPTION = "' + $finalEncryption + '" # Options: "Disabled", "Required", "Supported"' + [Environment]::NewLine
        
        if ($algorithmMismatch) {
            $outputContent += '# WARNING: Encryption algorithm discrepancy detected between servers' + [Environment]::NewLine
            $finalAlgorithm = ""
        } else {
            $finalAlgorithm = $primaryAlgorithm
        }
        $outputContent += '$ENCRYPTION_ALGORITHM = "' + $finalAlgorithm + '"     # Options: "Aes", "AesRC4", "None", "RC4", "RC4Aes"' + [Environment]::NewLine
        
        $outputContent += '$ENDPOINT_NAME = "' + $primaryEndpointName + '"      # Name of the mirroring endpoint to create' + [Environment]::NewLine
        $outputContent += '$MIRRORING_TIMEOUT = ' + $mirrorTimeout + '  # Timeout value in seconds for database mirroring' + [Environment]::NewLine
        
        # Save to file
        $outputFile = $OUTPUT_FILE
        $outputContent | Out-File -FilePath $outputFile -Force
        Write-Host "Configuration saved to: $outputFile" -ForegroundColor Green
        # Display the contents of the file
        Write-Host "`nConfiguration file contents:" -ForegroundColor Cyan
        Get-Content -Path $outputFile | ForEach-Object { Write-Host $_ }
    }
    catch {
        Write-Error "Error extracting mirroring configuration: $_"
    }
}

# NEW FUNCTION: Function for dynamic waiting based on polling
function Wait-ForSqlOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SqlInstance,
        
        [Parameter(Mandatory = $true)]
        [string]$Database,
        
        [Parameter(Mandatory = $true)]
        [string]$OperationType, # Values: "MirroringSuspend", "MirroringResume", "Restore", "ServiceRestart"
        
        [Parameter(Mandatory = $false)]
        [int]$MaxWaitSeconds = 120,
        
        [Parameter(Mandatory = $false)]
        [int]$PollIntervalSeconds = 2
    )
    
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($MaxWaitSeconds)
    $completed = $false
    
    Write-Host "Waiting for $OperationType operation to complete (timeout: $MaxWaitSeconds seconds)..." -ForegroundColor Yellow
    
    # Determine what to check based on operation type
    switch ($OperationType) {
        "MirroringSuspend" {
            # Loop until mirroring is suspended
            while ((Get-Date) -lt $endTime -and -not $completed) {
                Write-Host "." -NoNewline
                $status = Get-DbaDbMirror -SqlInstance $SqlInstance -Database $Database -ErrorAction SilentlyContinue
                
                if ($status -and $status.MirroringStatus -eq "Suspended") {
                    $completed = $true
                    Write-Host "`nDatabase mirroring successfully suspended" -ForegroundColor Green
                }
                else {
                    Start-Sleep -Seconds $PollIntervalSeconds
                }
            }
        }
        "MirroringResume" {
            # Loop until mirroring is synchronized
            while ((Get-Date) -lt $endTime -and -not $completed) {
                Write-Host "." -NoNewline
                $status = Get-DbaDbMirror -SqlInstance $SqlInstance -Database $Database -ErrorAction SilentlyContinue
                
                if ($status -and ($status.MirroringStatus -eq "Synchronized" -or $status.MirroringStatus -eq "Synchronizing")) {
                    $completed = $true
                    Write-Host "`nDatabase mirroring successfully resumed" -ForegroundColor Green
                }
                else {
                    Start-Sleep -Seconds $PollIntervalSeconds
                }
            }
        }
        "Restore" {
            # Loop until database is in restoring state
            while ((Get-Date) -lt $endTime -and -not $completed) {
                Write-Host "." -NoNewline
                $status = Get-DbaDatabase -SqlInstance $SqlInstance -Database $Database -ErrorAction SilentlyContinue
                
                if ($status -and $status.Status -eq "Restoring") {
                    $completed = $true
                    Write-Host "`nDatabase restore operation in progress" -ForegroundColor Green
                }
                else {
                    Start-Sleep -Seconds $PollIntervalSeconds
                }
            }
        }
        "ServiceRestart" {
            # Loop until SQL Server service is running
            $serverName = $SqlInstance.Split('\')[0]
            
            while ((Get-Date) -lt $endTime -and -not $completed) {
                Write-Host "." -NoNewline
                
                try {
                    # Try to connect to the instance
                    $conn = Connect-DbaInstance -SqlInstance $SqlInstance -ConnectTimeout 3 -ErrorAction Stop
                    $completed = $true
                    Write-Host "`nSQL Server service is running and accepting connections" -ForegroundColor Green
                    Disconnect-DbaInstance -SqlInstance $conn
                }
                catch {
                    # Check service status via sc.exe as fallback
                    $status = sc.exe \\$serverName query MSSQLSERVER
                    if ($status -match "RUNNING") {
                        Write-Host "`nService appears to be running but not yet accepting connections" -ForegroundColor Yellow
                    }
                    Start-Sleep -Seconds $PollIntervalSeconds
                }
            }
        }
    }
    
    # Check if we timed out
    if (-not $completed) {
        $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
        Write-Warning "Operation did not complete within the specified timeout ($elapsed seconds elapsed)"
        return $false
    }
    else {
        $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
        Write-Host "Operation completed in $elapsed seconds" -ForegroundColor Green
        return $true
    }
}

# Main execution logic
try {
    # Validate operation mode
    $validModes = @("REFRESH_MIRRORING_FROM_BACKUP", "REMOVE", "FAILOVER", "EXTRACT", "EMERGENCY_RECOVERY", 
                   "CHANGE_ENDPOINT_OWNER", "ADD_WITNESS", "SET_MIRRORING_TIMEOUT", "REFRESH_MIRRORING_ENDPOINT",
                   "REMOVE_WITNESS", "REMOVE_REFRESH_ENDPOINT")
    if ($validModes -notcontains $OPERATION_MODE) {
        Write-Error "Invalid operation mode: $OPERATION_MODE. Valid values are: $($validModes -join ', ')"
        exit
    }
    
    Write-Host "Using database mirroring script with improved setup and recovery process" -ForegroundColor Green
    Write-Host "Operation mode: $OPERATION_MODE" -ForegroundColor Yellow
    Write-Host "Excluded databases: $($EXCLUDED_DATABASES -join ', ')" -ForegroundColor Yellow
    
    # Special handling for EMERGENCY_RECOVERY mode
    if ($OPERATION_MODE -eq "EMERGENCY_RECOVERY") {
        if ([string]::IsNullOrWhiteSpace($EMERGENCY_SERVER)) {
            Write-Error "EMERGENCY_SERVER parameter must be specified for EMERGENCY_RECOVERY mode."
            exit
        }
        
        Write-Host "Running emergency recovery mode for server: $EMERGENCY_SERVER" -ForegroundColor Red
        Emergency-RecoverMirroringDatabases -SqlServer $EMERGENCY_SERVER -DatabaseList $DATABASE_LIST.Split(',')
        exit
    }
    
    # Test connection to primary server for other modes
    Write-Host "Testing connection to $PRIMARY_SERVER..." -ForegroundColor Yellow
    try {
        $primaryConnection = Test-DbaConnection -SqlInstance $PRIMARY_SERVER
        if ($primaryConnection.ConnectSuccess) {
            Write-Host "Successfully connected to $PRIMARY_SERVER" -ForegroundColor Green
        }
        else {
            Write-Error "Failed to connect to $PRIMARY_SERVER. Error: $($primaryConnection.ConnectError)"
            exit
        }
    }
    catch {
        Write-Error "Failed to connect to $PRIMARY_SERVER. Exception: $_"
        exit
    }
    
    switch ($OPERATION_MODE) {
        "EXTRACT" {
            Extract-MirroringConfig
        }
        "REFRESH_MIRRORING_FROM_BACKUP" {
            # Add extra check to verify required parameters
            if ([string]::IsNullOrWhiteSpace($PRIMARY_SERVER) -or [string]::IsNullOrWhiteSpace($MIRROR_SERVER)) {
                Write-Host "ERROR: PRIMARY_SERVER and MIRROR_SERVER must be specified for refresh." -ForegroundColor Red
                exit
            }
            
            # Call the Refresh-MirroringFromBackup function directly - it now handles database lists internally
            $refreshResult = Refresh-MirroringFromBackup -PrimaryServer $PRIMARY_SERVER -MirrorServer $MIRROR_SERVER -WitnessServer $WITNESS_SERVER -DatabaseList $DATABASE_LIST -ExcludedDatabases $EXCLUDED_DATABASES -BackupFolder $BACKUP_FOLDER -AlwaysCreateNewBackup $ALWAYS_CREATE_NEW_BACKUP -ForceOperation $FORCE_OPERATION -EnableCompression $ENABLE_BACKUP_COMPRESSION -EnableChecksum $ENABLE_BACKUP_CHECKSUM -EnableVerify $ENABLE_BACKUP_VERIFY -CreateFolder $CREATE_BACKUP_FOLDER -FileMapping $CUSTOM_FILE_MAPPING -MaxTransferSize $MAX_TRANSFER_SIZE -BlockSize $BLOCK_SIZE -BufferCount $BUFFER_COUNT
            
            if ($refreshResult) {
                Write-Host "Mirroring refresh operation completed successfully." -ForegroundColor Green
            } else {
                Write-Warning "Mirroring refresh operation completed with some issues. See log for details."
            }
        }
        "REMOVE" {
            Remove-MirroringWithDbaTools
        }
        "FAILOVER" {
            Failover-MirroringWithDbaTools
        }
        "CHANGE_ENDPOINT_OWNER" {
            # Set endpoint owner on primary server
            $primaryResult = Set-EndpointOwner -SqlInstance $PRIMARY_SERVER -EndpointName $ENDPOINT_NAME -CreateLoginIfNotExists -Force:$FORCE_OPERATION
            
            # Set endpoint owner on mirror server
            $mirrorResult = Set-EndpointOwner -SqlInstance $MIRROR_SERVER -EndpointName $ENDPOINT_NAME -CreateLoginIfNotExists -Force:$FORCE_OPERATION
            
            # Set endpoint owner on witness server if specified
            $witnessResult = $true
            if (-not [string]::IsNullOrWhiteSpace($WITNESS_SERVER)) {
                $witnessResult = Set-EndpointOwner -SqlInstance $WITNESS_SERVER -EndpointName $ENDPOINT_NAME -CreateLoginIfNotExists -Force:$FORCE_OPERATION
            }
            
            # Display overall result
            if ($primaryResult -and $mirrorResult -and $witnessResult) {
                Write-Host "Successfully changed endpoint owners on all servers." -ForegroundColor Green
            } else {
                Write-Host "Endpoint owner change operations completed with issues. See above messages for details." -ForegroundColor Yellow
            }
        }
        "ADD_WITNESS" {
            Add-MirroringWitness -SqlInstance $PRIMARY_SERVER -WitnessServer $WITNESS_SERVER -DatabaseList $DATABASE_LIST -ExcludedDatabases $EXCLUDED_DATABASES -MirroringPort $MIRRORING_PORT -EndpointName $ENDPOINT_NAME -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Confirm:(-not $FORCE_OPERATION)
        }
        "REMOVE_WITNESS" {
            # Remove witness from mirrored databases
            Remove-MirroringWitness -SqlInstance $PRIMARY_SERVER -DatabaseList $DATABASE_LIST -ExcludedDatabases $EXCLUDED_DATABASES
        }
        "SET_MIRRORING_TIMEOUT" {
            # Use the new function to set timeout values
            Set-MirroringTimeout -SqlInstance $PRIMARY_SERVER -TimeoutValue $MIRRORING_TIMEOUT -DatabaseList $DATABASE_LIST -Force:$FORCE_OPERATION
        }
        "REFRESH_MIRRORING_ENDPOINT" {
            # Create/refresh endpoints on all servers
            Write-Host "=== Refreshing Database Mirroring Endpoints ===" -ForegroundColor Cyan
            
            $primaryEndpoint = Refresh-CreateEndpoint -ServerInstance $PRIMARY_SERVER -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Role "ALL" -PreservePermissions $false
            
            $mirrorEndpoint = Refresh-CreateEndpoint -ServerInstance $MIRROR_SERVER -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Role "ALL" -PreservePermissions $false
            
            if (-not [string]::IsNullOrWhiteSpace($WITNESS_SERVER)) {
                $witnessEndpoint = Refresh-CreateEndpoint -ServerInstance $WITNESS_SERVER -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Role "WITNESS" -PreservePermissions $true
            }
            
            # Setup permissions between servers
            Setup-EndpointPermissions -PrimaryServer $PRIMARY_SERVER -MirrorServer $MIRROR_SERVER -WitnessServer $WITNESS_SERVER
            
            Write-Host "Successfully refreshed mirroring endpoints on all servers." -ForegroundColor Green
        }
        "REMOVE_REFRESH_ENDPOINT" {
            # Force drop and recreate endpoints on all servers at once
            Write-Host "=== Force Removing and Recreating Database Mirroring Endpoints ===" -ForegroundColor Cyan
            
            # Call the new function that handles all servers at once
            $refreshResult = Remove-Refresh-EndPoint -PrimaryServer $PRIMARY_SERVER -MirrorServer $MIRROR_SERVER -WitnessServer $WITNESS_SERVER -EndpointName $ENDPOINT_NAME -Port $MIRRORING_PORT -Encryption $ENDPOINT_ENCRYPTION -Algorithm $ENCRYPTION_ALGORITHM -Force:$FORCE_OPERATION
            
            if ($refreshResult) {
                Write-Host "Successfully dropped and recreated mirroring endpoints on all servers." -ForegroundColor Green
            } else {
                Write-Warning "Completed endpoint recreation with some issues. See log for details."
            }
        }
    }
}
catch {
    Write-Error "An error occurred during script execution: $_"
}
finally {
    Write-Host "Script execution completed." -ForegroundColor Cyan
}
