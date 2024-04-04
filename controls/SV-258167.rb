control 'SV-258167' do
  title 'RHEL 8 audit logs must have a mode of 0600 or less permissive to
prevent unauthorized read access.'
  desc "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements."
  desc 'check', 'Verify the audit logs have a mode of "0600" or less permissive.

    First, determine where the audit logs are stored with the following command:

    $ sudo grep -iw log_file /etc/audit/auditd.conf

    log_file = /var/log/audit/audit.log

    Using the location of the audit log file, check if the audit log has a mode
of "0600" or less permissive with the following command:

    $ sudo stat -c "%a %n" /var/log/audit/audit.log

    600 /var/log/audit/audit.log

    If the audit log has a mode more permissive than "0600", this is a
finding.'
  desc 'fix', 'Configure the audit log to be protected from unauthorized read access by setting the correct permissive mode with the following command:

$ sudo chmod 0600 /var/log/audit/audit.log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag gid: 'V-230396'
  tag rid: 'SV-258167r902733_rule'
  tag stig_id: 'RHEL-08-030070'
  tag fix_id: 'F-33040r902732_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file

  describe file(log_file) do
    it { should_not be_more_permissive_than('0600') }
  end
end
