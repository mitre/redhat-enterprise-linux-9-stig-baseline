control 'SV-257806' do
  title 'RHEL 9 must be configured to disable the FireWire kernel module.'
  desc 'Disabling firewire protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the firewire-core kernel module with the following command:

$ sudo grep -r firewire-core /etc/modprobe.conf /etc/modprobe.d/*

blacklist firewire-core

If the command does not return any output, or the line is commented out, and use of firewire-core is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the firewire-core kernel module from being loaded, add the following line to the file /etc/modprobe.d/firewire-core.conf (or create firewire-core.conf if it does not exist):

install firewire-core /bin/false
blacklist firewire-core'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257806'
  tag rid: 'SV-257806r942955_rule'
  tag stig_id: 'RHEL-09-213055'
  tag fix_id: 'F-61471r942954_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe kernel_module('firewire_core') do
    it { should be_disabled }
    it { should be_blacklisted }
  end

  config_files = command('find /etc/modprobe.conf /etc/modprobe.d/* -print0').stdout.split("\0")
  blacklisted = config_files.any? do |c|
    params = parse_config_file(c, comment_char: '#', multiple_values: true,
                                  assignment_regex: /^(\S+)\s+(\S+)$/).params
    params.include?('blacklist') and params['blacklist'].include?('firewire-core')
  end

  describe 'firewire_core' do
    it 'is configured to be blacklisted' do
      expect(blacklisted).to eq(true)
    end
  end
end
