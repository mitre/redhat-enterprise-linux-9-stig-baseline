control 'SV-258118' do
  title 'RHEL 9 must not be configured to bypass password requirements for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', 'Verify the operating system is not configured to bypass password requirements for privilege escalation with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo

If any occurrences of "pam_succeed_if" are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Remove any occurrences of " pam_succeed_if " in the  "/etc/pam.d/sudo" file.'
  impact 0.5
  tag check_id: 'C-61859r926339_chk'
  tag severity: 'medium'
  tag gid: 'V-258118'
  tag rid: 'SV-258118r1050789_rule'
  tag stig_id: 'RHEL-09-611145'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-61783r926340_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  if virtualization.system.eql?('docker') && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container without sudo enabled' do
      skip 'Control not applicable within a container without sudo enabled'
    end
  else
    describe parse_config_file('/etc/pam.d/sudo') do
      its('content') { should_not match(/pam_succeed_if/) }
    end
  end
end
