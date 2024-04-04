control 'SV-258229' do
  title 'RHEL 8 audit system must protect auditing rules from unauthorized
change.'
  desc 'Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 system activity.

    In immutable mode, unauthorized users cannot execute changes to the audit
system to potentially hide malicious activity and then put the audit rules
back.  A system reboot would be noticeable and a system administrator could
then investigate the unauthorized changes.'
  desc 'check', 'Verify the audit system prevents unauthorized changes with the following
command:

    $ sudo grep "^\\s*[^#]" /etc/audit/audit.rules | tail -1

    -e 2

    If the audit system is not set to be immutable by adding the "-e 2"
option to the "/etc/audit/audit.rules", this is a finding.'
  desc 'fix', 'Configure the audit system to set the audit rules to be immutable by adding
the following line to "/etc/audit/rules.d/audit.rules"

    -e 2

    Note: Once set, the system must be rebooted for auditing to be changed.  It
is recommended to add this option as the last step in securing the system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag gid: 'V-230402'
  tag rid: 'SV-258229r627750_rule'
  tag stig_id: 'RHEL-08-030121'
  tag fix_id: 'F-33046r567953_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe command('grep "^\s*[^#]" /etc/audit/audit.rules | tail -1') do
    its('stdout.strip') { should cmp '-e 2' }
  end
end
