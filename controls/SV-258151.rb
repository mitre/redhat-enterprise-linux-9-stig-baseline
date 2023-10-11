control 'SV-258151' do
  title 'RHEL 9 audit package must be installed.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured RHEL 9 system.

'
  desc 'check', 'Verify that RHEL 9 audit service package is installed.

Check that the audit service package is installed with the following command:

$ sudo dnf list --installed audit

Example output:

audit-3.0.7-101.el9_0.2.x86_64

If the "audit" package is not installed, this is a finding.'
  desc 'fix', 'Install the audit service package (if the audit service is not already installed) with the following command:

$ sudo dnf install audit'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61892r926438_chk'
  tag severity: 'medium'
  tag gid: 'V-258151'
  tag rid: 'SV-258151r926440_rule'
  tag stig_id: 'RHEL-09-653010'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-61816r926439_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000055-GPOS-00026']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-000159', 'CCI-000169', 'CCI-000172', 'CCI-001464', 'CCI-001487', 'CCI-001814', 'CCI-001875', 'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-001914', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-6 (4)', 'AU-7 (1)', 'AU-8 a', 'AU-12 a', 'AU-12 c', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 b', 'AU-7 b', 'AU-8 b', 'AU-12 (3)', 'MA-4 (1) (a)']
end
