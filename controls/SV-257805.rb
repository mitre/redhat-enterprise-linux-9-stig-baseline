control 'SV-257805' do
  title 'RHEL 9 must be configured to disable the Controller Area Network kernel module.'
  desc 'Disabling Controller Area Network (CAN) protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the CAN kernel module with the following command:

$ grep -r can /etc/modprobe.conf /etc/modprobe.d/* 

install can /bin/false
blacklist can

If the command does not return any output, or the lines are commented out, and use of CAN is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the can kernel module from being loaded, add the following lines to the file  /etc/modprobe.d/can.conf (or create can.conf if it does not exist):

install can /bin/false
blacklist can'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257805'
  tag rid: 'SV-257805r1044856_rule'
  tag stig_id: 'RHEL-09-213050'
  tag fix_id: 'F-61470r1044855_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe kernel_module('can') do
    it { should be_disabled }
    it { should be_blacklisted }
  end
end
