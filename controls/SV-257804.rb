control 'SV-257804' do
  title 'RHEL 9 must be configured to disable the Asynchronous Transfer Mode kernel module.'
  desc 'Disabling Asynchronous Transfer Mode (ATM) protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the ATM kernel module with the following command:

$ sudo grep -r atm /etc/modprobe.conf /etc/modprobe.d/*

blacklist atm

If the command does not return any output, or the line is commented out, and use of ATM is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the atm kernel module from being loaded, add the following line to the file  /etc/modprobe.d/atm.conf (or create atm.conf if it does not exist):

install atm /bin/false
blacklist atm'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257804'
  tag rid: 'SV-257804r925399_rule'
  tag stig_id: 'RHEL-09-213045'
  tag fix_id: 'F-61469r925398_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe kernel_module('atm') do
    it { should be_disabled }
    it { should be_blacklisted }
  end

  config_files = command('find /etc/modprobe.conf /etc/modprobe.d/* -print0').stdout.split("\0")
  blacklisted = config_files.any? do |c|
    params = parse_config_file(c, comment_char: '#', multiple_values: true,
                                  assignment_regex: /^(\S+)\s+(\S+)$/).params
    params.include?('blacklist') and params['blacklist'].include?('atm')
  end

  describe 'atm' do
    it 'is configured to be blacklisted' do
      expect(blacklisted).to eq(true)
    end
  end
end
