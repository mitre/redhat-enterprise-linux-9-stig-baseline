control 'SV-257808' do
  title 'RHEL 9 must disable the Transparent Inter Process Communication (TIPC) kernel module.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The Transparent Inter Process Communication (TIPC) is a protocol that is specially designed for intra-cluster communication. It can be configured to transmit messages either on UDP or directly across Ethernet. Message delivery is sequence guaranteed, loss free and flow controlled. Disabling TIPC protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the tipc kernel module with the following command:

$ sudo grep -r tipc /etc/modprobe.conf /etc/modprobe.d/*

blacklist tipc

If the command does not return any output, or the line is commented out, and use of tipc is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the tipc kernel module from being loaded, add the following line to the file  /etc/modprobe.d/tipc.conf (or create tipc.conf if it does not exist):

install tipc /bin/false
blacklist tipc'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-257808'
  tag rid: 'SV-257808r925411_rule'
  tag stig_id: 'RHEL-09-213065'
  tag fix_id: 'F-61473r925410_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe kernel_module('tipc') do
    it { should be_disabled }
    it { should be_blacklisted }
  end

  config_files = command('find /etc/modprobe.conf /etc/modprobe.d/* -print0').stdout.split("\0")
  blacklisted = config_files.any? do |c|
    params = parse_config_file(c, comment_char: '#', multiple_values: true,
                                  assignment_regex: /^(\S+)\s+(\S+)$/).params
    params.include?('blacklist') and params['blacklist'].include?('tipc')
  end

  describe 'tipc' do
    it 'is configured to be blacklisted' do
      expect(blacklisted).to eq(true)
    end
  end
end
