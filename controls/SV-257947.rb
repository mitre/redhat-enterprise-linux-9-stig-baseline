control 'SV-257947' do
  title 'RHEL 9 must disable network management of the chrony daemon.'
  desc 'Not exposing the management interface of the chrony daemon on the network diminishes the attack space.'
  desc 'check', 'Verify RHEL 9 disables network management of the chrony daemon with the following command:

$ grep -w cmdport /etc/chrony.conf

cmdport 0

If the "cmdport" option is not set to "0", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable network management of the chrony daemon by adding/modifying the following line in the /etc/chrony.conf file:

cmdport 0'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-257947'
  tag rid: 'SV-257947r958480_rule'
  tag stig_id: 'RHEL-09-252030'
  tag fix_id: 'F-61612r925827_fix'
  tag cci: ['CCI-000381', 'CCI-000382']
  tag nist: ['CM-7 a', 'CM-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/chrony.conf').exist?)
  }

  chrony_conf = ntp_conf('/etc/chrony.conf')

  describe chrony_conf do
    its('cmdport') { should cmp 0 }
  end
end
