control 'SV-258039' do
  title 'RHEL 9 Bluetooth must be disabled.'
  desc 'This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 9 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice and pointing devices, and near field communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the Authorizing Official (AO). Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 9 operating system.

'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the Bluetooth kernel module with the following command:

$ sudo grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d/* 

blacklist bluetooth

If the command does not return any output, or the line is commented out, and use of Bluetooth is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the Bluetooth adapter when not in use.

Create or modify the "/etc/modprobe.d/bluetooth.conf" file with the following line:

install bluetooth /bin/false
blacklist bluetooth

Reboot the system for the settings to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61780r926102_chk'
  tag severity: 'medium'
  tag gid: 'V-258039'
  tag rid: 'SV-258039r926104_rule'
  tag stig_id: 'RHEL-09-291035'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61704r926103_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001443']
  tag nist: ['CM-7 a', 'AC-18 (1)']
end
