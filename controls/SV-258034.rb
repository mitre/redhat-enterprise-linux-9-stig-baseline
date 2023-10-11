control 'SV-258034' do
  title 'RHEL 9 must be configured to disable USB mass storage.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the USB Storage kernel module with the following command:

$ sudo grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d/* 

blacklist usb-storage

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the usb-storage kernel module from being loaded, add the following line to the file  /etc/modprobe.d/usb-storage.conf (or create usb-storage.conf if it does not exist):

install usb-storage /bin/false
blacklist usb-storage'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61775r926087_chk'
  tag severity: 'medium'
  tag gid: 'V-258034'
  tag rid: 'SV-258034r926089_rule'
  tag stig_id: 'RHEL-09-291010'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61699r926088_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
end
