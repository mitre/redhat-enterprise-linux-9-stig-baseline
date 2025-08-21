control 'SV-258167' do
  title 'RHEL 9 audit logs file must have mode 0600 or less permissive to prevent unauthorized access to the audit log.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 9 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify the audit logs have a mode of "0600".

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine the mode of each audit log with the following command:

$ sudo find /var/log/audit/ -type f -exec stat -c '%a %n' {} \;

rw-------. 2 root root 237923 Jun 11 11:56 /var/log/audit/audit.log

If the audit logs have a mode more permissive than "0600", this is a finding.)
  desc 'fix', 'Configure the audit logs to have a mode of "0600" with the following command:

Replace "[audit_log_file]" with the path to each audit log file. By default, these logs are located in "/var/log/audit/.

$ sudo chmod 0600 /var/log/audit/[audit_log_file]

Check the group that owns the system audit logs:

$ sudo grep -iw log_group /etc/audit/auditd.conf

If log_group is set to a user other than root, configure the permissions the following way:

$ sudo chmod 0640 $log_file
$ sudo chmod 0440 $log_file.*

Otherwise, configure the permissions the following way:

$ sudo chmod 0600 $log_file
$ sudo chmod 0400 $log_file.*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag gid: 'V-258167'
  tag rid: 'SV-258167r1045306_rule'
  tag stig_id: 'RHEL-09-653090'
  tag fix_id: 'F-61832r1045305_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9', 'AU-9 a', 'SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file

  describe file(log_file) do
    it { should_not be_more_permissive_than('0600') }
  end
end
