control 'SV-257805' do
  title 'RHEL 9 must be configured to disable the Controller Area Network kernel module.'
  desc 'Disabling Controller Area Network (CAN) protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the CAN kernel module with the following command:

$ sudo grep -r can /etc/modprobe.conf /etc/modprobe.d/*

blacklist can

If the command does not return any output, or the line is commented out, and use of CAN is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the can kernel module from being loaded, add the following line to the file  /etc/modprobe.d/can.conf (or create atm.conf if it does not exist):

install can /bin/false
blacklist can'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257805'
  tag rid: 'SV-257805r925402_rule'
  tag stig_id: 'RHEL-09-213050'
  tag fix_id: 'F-61470r925401_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('can_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe kernel_module('can') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
