control 'SV-258228' do
  title 'RHEL 8 audit system must protect logon UIDs from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit RHEL 8 system activity.

    In immutable mode, unauthorized users cannot execute changes to the audit
system to potentially hide malicious activity and then put the audit rules
back.  A system reboot would be noticeable and a system administrator could
then investigate the unauthorized changes.'
  desc 'check', 'Verify the audit system prevents unauthorized changes to logon UIDs with
the following command:

    $ sudo grep -i immutable /etc/audit/audit.rules

    --loginuid-immutable

    If the login UIDs are not set to be immutable by adding the
"--loginuid-immutable" option to the "/etc/audit/audit.rules", this is a
finding.'
  desc 'fix', 'Configure the audit system to set the logon UIDs to be immutable by adding
the following line to "/etc/audit/rules.d/audit.rules"

    --loginuid-immutable'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag gid: 'V-230403'
  tag rid: 'SV-258228r627750_rule'
  tag stig_id: 'RHEL-08-030122'
  tag fix_id: 'F-33047r567956_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe command('grep -i immutable /etc/audit/audit.rules') do
    its('stdout.strip') { should cmp '--loginuid-immutable' }
  end
end
