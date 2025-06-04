# build-vbox.ps1 – Automate VM creation and Windows installation using VirtualBox

# Paths
$vmName      = "AutomatedWin10"
$vmFolder    = "C:\ISO Folder"
$winISO      = "$vmFolder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO   = "$vmFolder\answer.iso"
$vdiFile     = "$vmFolder\AutomatedWin10.vdi"

# Create VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name $vmName --register

# Modify VM settings
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm $vmName --memory 4096 --cpus 2 --ostype "Windows10_64"

# Create virtual hard disk (40 GB)
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename $vdiFile --size 40000

# Add SATA controller and attach VHD
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "SATA Controller" --add sata --controller IntelAhci
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $vdiFile

# Add IDE controller and attach ISOs
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "IDE Controller" --add ide
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium $winISO
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium $answerISO

# Enable NAT networking
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm $vmName --nic1 nat

# Start the VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm $vmName
