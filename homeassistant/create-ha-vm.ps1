#Requires -RunAsAdministrator
<#
  Creates the Home Assistant OS virtual machine on this Hyper-V host.

  Run once, from an *elevated* PowerShell (right-click > Run as administrator):
      powershell -ExecutionPolicy Bypass -File C:\netmon\homeassistant\create-ha-vm.ps1

  Follows the official Hyper-V steps (home-assistant.io/installation/windows):
  Generation 2 VM, existing VHDX, bridged (external) switch, Secure Boot off.
#>
param(
    [string]$Name    = "HomeAssistant",
    [string]$Switch  = "External VM Switch",
    [string]$Source  = "$env:USERPROFILE\Downloads\haos-18.3\haos_ova-18.3.vhdx",
    [int64] $Memory  = 4GB,
    [int]   $Cpus    = 2,
    [int64] $DiskSize = 32GB
)
$ErrorActionPreference = "Stop"

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "A VM called '$Name' already exists - nothing changed." }
if (-not (Test-Path $Source)) { throw "Image not found: $Source" }
if (-not (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) {
    throw "Virtual switch '$Switch' not found. Available: $((Get-VMSwitch).Name -join ', ')"
}

# keep the disk with your other VM disks
$diskDir = Join-Path (Get-VMHost).VirtualHardDiskPath $Name
New-Item -ItemType Directory -Force $diskDir | Out-Null
$disk = Join-Path $diskDir (Split-Path $Source -Leaf)
Write-Host "Copying disk to $disk ..."
Copy-Item $Source $disk

if ((Get-VHD $disk).Size -lt $DiskSize) { Resize-VHD -Path $disk -SizeBytes $DiskSize }

New-VM -Name $Name -Generation 2 -MemoryStartupBytes $Memory -VHDPath $disk -SwitchName $Switch | Out-Null
Set-VMProcessor -VMName $Name -Count $Cpus
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false
Set-VMFirmware -VMName $Name -EnableSecureBoot Off
# start with the server, shut down cleanly with it
Set-VM -Name $Name -AutomaticStartAction Start -AutomaticStopAction ShutDown

Start-VM -Name $Name
Write-Host ""
Write-Host "Started '$Name'. First boot takes a few minutes."
Write-Host "Then open  http://homeassistant.local:8123  from any device at home"
Write-Host "(or find its IP in your router's device list, look for 'homeassistant')."
