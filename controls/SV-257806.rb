control 'SV-257806' do
  title 'RHEL 9 must be configured to disable the FireWire kernel module.'
  desc 'Disabling firewire protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the firewire-core kernel module with the following command:

$ sudo grep -r firewire-core /etc/modprobe.conf /etc/modprobe.d/* 

blacklist firewire-core

If the command does not return any output, or the line is commented out, and use of firewire-core is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the firewire-core kernel module from being loaded, add the following line to the file /etc/modprobe.d/firewire-core.conf (or create firewire-core.conf if it does not exist):

install firewire-core /bin/true
blacklist firewire-core'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61547r925403_chk'
  tag severity: 'medium'
  tag gid: 'V-257806'
  tag rid: 'SV-257806r928942_rule'
  tag stig_id: 'RHEL-09-213055'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61471r928942_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
