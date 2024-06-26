control 'SV-257946' do
  title 'RHEL 9 must disable the chrony daemon from acting as a server.'
  desc 'Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface.'
  desc 'check', 'Verify RHEL 9 disables the chrony daemon from acting as a server with the following command:

$ grep -w port /etc/chrony.conf

port 0

If the "port" option is not set to "0", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the chrony daemon from acting as a server by adding/modifying the following line in the /etc/chrony.conf file:

port 0'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-257946'
  tag rid: 'SV-257946r925825_rule'
  tag stig_id: 'RHEL-09-252025'
  tag fix_id: 'F-61611r925824_fix'
  tag cci: ['CCI-000381', 'CCI-000382']
  tag nist: ['CM-7 a', 'CM-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/chrony.conf').exist?)
  }

  chrony_conf = ntp_conf('/etc/chrony.conf')

  describe chrony_conf do
    its('port') { should cmp 0 }
  end
end
