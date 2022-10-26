function Convert-IntelDrop {
    <#
    .Author
    Tanner Hansen
    .Synopsis
    This function imports a given Excel document, converts it to either the Splunk or HX format, and outputs the new file in the working directory.
    .Parameter IntelDrop
    The Excel Document which needs converting. This document should be the standard format which Intel Provides.
    .Parameter Splunk
    Flag to convert the IntelDrop into the Splunk format. If both this and HX are not included, both are processed.
    .Parameter SplunkOutput
    Which file the function will output the Splunk format. Defaults to "MSOC 2 Week.csv". This file must be a csv.
    .Parameter HX
    Flag to convert the IntelDrop into the HX format. If both this and Splunk are not included, both are processed.
    .Parameter HXOutput
    Which directory the function will output the HX formatted files. Defaults to "hx".
    .Parameter Quiet
    This will silence the various Write-Host commands.
    .Example
    Convert-IntelDrop "20221011 IOCs.xlsx"
    This is the most basic way to run this command. This will import the xlsx file and convert to both of the formats and output to the default for both.
    .Example
    Convert-IntelDrop "20221011 IOCs.xlsx" -HX -HXOutput "new_hx_rules"
    This will only convert to the HX format, and output to "new_hx_rules". To convert to Splunk instead, swap -HX and -HXOutput to -Splunk and -SplunkOutput.
    #>
    param(
        [Parameter(Mandatory)][string]$IntelDrop,
        [switch]$Splunk,
        [switch]$HX,
        [switch]$Quiet,
        [switch]$Count,
        [string]$SplunkOutput,
        [string]$HXOutput
    )

    PROCESS {
        #If neither Splunk or HX was selected, assume both
        if ($Splunk -ne $true -and $HX -ne $true) {
            $Splunk = $true
            $HX = $true
        }

        #Setting Default value for HX and Splunk Outputs and making sure outputs are the right filetype
        if ($SplunkOutput -eq "") { $SplunkOutput = "MSOC 2 Week.csv" }
        if ($SplunkOutput.EndsWith(".csv") -eq $false) { 
            Write-Error "ERROR: -SplunkOutput must be set to a .csv file!"
            return
        }
        if ($HXOutput -eq "") { $HXOutput = "hx" }

        #### BEGIN IMPORT ####
        if ($Quiet -ne $true) { 
            Write-Host "Importing:"(Get-Item $IntelDrop).Name
        }
        $IOC_List = Import-IntelDrop $IntelDrop

        #Used for final IOC counts
        $true_total = 0
        #### SPLUNK FORMATTING ####
        if ($Splunk -eq $true) {
            $Combined = Create-SplunkTable -IOCList $IOC_List
            $true_total = $true_total + $Combined.count()
            $Combined | Export-Csv $SplunkOutput
        }

        #### HX FORMATTING #### 
        if ($HX -eq $true) {
            ## Slicing Columns ##
            if ($Quiet -ne $true) { Write-Host "`n###Starting HX Formatting###`n" }
            if ($Quiet -ne $true) { Write-Host "Slicing Fields" }
            $Combined = $IOC_List | Where-Object {$_.type -eq "hash_md5" -or $_.type -eq "ip_address" -or $_.type -eq "domain"} | Select-Object -ExpandProperty indicator | Sort | Get-Unique
            
            ## Output Directory Management ##
            if (Test-Path $HXOutput) {
                if ($Quiet -ne $true) { Write-Host "Cleaning $HXOutput" }
                Get-ChildItem $HXOutput -Filter "hx_rule_*.txt" | Remove-Item
            }
            else {
                if ($Quiet -ne $true) { Write-Host "Creating $HXOutput" }
                New-Item -ItemType Directory $HXOutput
            }
            
            ## Exporting Data to Output Directory
            if ($Quiet -ne $true) { Write-Host "Exporting HX Lists to $HXOutput" }
            $maxSize = 10000
            $parts = [Math]::Ceiling($Combined.count / $maxSize)
            for ($i = 1; $i -le $parts; $i++) {
                $start = (($i-1)*$maxSize)
                $end = (($i)*$maxSize) - 1
                if ($end -ge $Combined.count) { $end = $Combined.count }
                $Combined[$start..$end] | Out-File "$HXOutput\hx_rule_$i.txt" -Encoding ascii
            }

            if ($Splunk -eq $true) { $true_total = $true_total + ($IOC_List | Where-Object {$_.type -eq "hash_md5"} | Select-Object -ExpandProperty indicator| Sort | Get-Unique).Count } 
            else { $true_total = $true_total + $Combined.Count }

            ## Diagnostic ##
            if ($Quiet -ne $true) { 
                Write-Host "`n#######HX DIAGNOSTICS#######`n"
                Write-Host "Total IOCs Processed: " $Combined.Count 
                Write-Host "Total Files Produced: " $parts
                Write-Host "`n############################"
            }
        }

        ## Final Diagnostic ##
        if ($Quiet -ne $true) {
                Write-Host "`n####TOTAL IOCs Processed####`n"
                Write-Host "Total Unique IOCs Processed: " $true_total
                Write-Host "`n############################"
        }
    }
}

function Get-ArrayValue {
    <#
    .Synopsis
    Helper Function for creating the Splunk Row. Do not use for anything else.
    #>
    param (
        [Parameter(Mandatory)][System.Array]$Array,
        [Parameter(Mandatory)][int]$Index
    )

    PROCESS {
        if ($Index -ge $Array.Length) { return "" }
        else { return $Array.get($Index) } 
    }
}

function Create-SplunkRow {
    param (
        [string]$Domain,
        [string]$IP,
        [string]$URL,
        [string]$Date
    )
    PROCESS {
        return [PSCustomObject]@{
            Domain = $Domain
            IP = $IP
            URL = $URL
            Date = $Date
        }
    }
}

function Create-SplunkTable {
    param (
        [switch]$Quiet,
        $IOCList
    )

    PROCESS {
        ## Slicing Columns ##
        if ($Quiet -ne $true) { Write-Host "`n###Starting Splunk Formatting###`n" }
        if ($Quiet -ne $true) { Write-Host "Slicing Domains" }
        $Domains = $IOC_List | Where-Object {$_.type -eq "domain"} | Select-Object -ExpandProperty indicator | Sort | Get-Unique
        if ($Quiet -ne $true) { Write-Host "Slicing IP Addresses" }
        $IPs = $IOC_List | Where-Object {$_.type -eq "ip_address"} | Select-Object -ExpandProperty indicator | Sort | Get-Unique
        if ($Quiet -ne $true) { Write-Host "Slicing URLs" }
        $URLs = $IOC_List | Where-Object {$_.type -eq "url"} | Select-Object -ExpandProperty indicator | Sort | Get-Unique

        $Combined = [System.Collections.ArrayList]@()

        ## Row Formatting ## 
        $HighVal = 0
        if ($Domains.Count -gt $HighVal) { $HighVal = $Domains.Count }
        if ($IP.Count -gt $HighVal) { $HighVal = $IPs.Count }
        if ($URL.Count -gt $HighVal) { $HighVal = $URLs.Count }

        if ($Quiet -ne $true) { Write-Host "Building List" }

        $Row = Create-SplunkRow -Domain (Get-ArrayValue -Array $Domains -Index 0) -IP (Get-ArrayValue -Array $IPs -Index 0) -URL (Get-ArrayValue -Array $URLs -Index 0) -Date (Get-Date -Format "yyyyMMdd")

        $Combined.Add($Row) > $null

        For ($i = 1; $i -lt $HighVal; $i++) {
            $Row = Create-SplunkRow -Domain (Get-ArrayValue -Array $Domains -Index $i) -IP (Get-ArrayValue -Array $IPs -Index $i) -URL (Get-ArrayValue -Array $URLs -Index $i) -Date ""
            $Combined.Add($Row) > $null
        }

        ## Diagnostic Info ##
        if ($Quiet -ne $true) { 
            Write-Host "`n#####SPLUNK DIAGNOSTICS#####`n"
            Write-Host "Domain IOCs: " $Domains.Count 
            Write-Host "IP IOCs: " $IPs.Count 
            Write-Host "URL IOCs: " $URLs.Count 
            $Total = $Domains.Count + $IPs.Count + $URLs.Count
            Write-Host "`nTotal IOCs Processed: $Total"
            Write-Host "`n############################"
        }
        return $Combined
    }
}

function Import-IntelDrop {
    param (
        [Parameter(Position=0,Mandatory)][string]$IntelDrop
    )

    PROCESS {
        #Verifying IntelDrop is readable and an excel doc
        if ((Test-Path -Path $IntelDrop) -eq $False) {
            Write-Error "ERROR: $IntelDrop PATH INVALID OR UNREADABLE. Exiting..."
            return
        }
        if ((Get-Item $IntelDrop).Extension -ne ".xlsx" -and (Get-Item $IntelDrop).Extension -ne ".xls") {
            Write-Error "ERROR: $IntelDrop FILETYPE INVALID. Expecting .xlsx or .xls filetype. Exiting..."
            return
        }
        return ExcelToCsv($IntelDrop)
    }
}

 Function ExcelToCsv ($File) {
     $Excel = New-Object -ComObject Excel.Application
     $Excel.DisplayAlerts = $False
     $FileName = (Get-Item $File).BaseName
     $wb = $Excel.Workbooks.Open($File)
     $folder = New-Item "tmp" -ItemType Directory
     foreach ($ws in $wb.Worksheets) {
        $n = $FileName + "_" + $ws.Name
        $ws.SaveAs($folder.FullName + "\" + $n + ".csv",6)
     }
     $Excel.Quit()

     $Data = Import-Csv -Path (Get-ChildItem -Path $folder.FullName -Filter '*.csv').FullName
     Remove-Item $folder -Recurse
     return $Data
 }