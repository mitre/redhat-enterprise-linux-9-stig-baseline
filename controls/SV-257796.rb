control 'SV-257796' do
  title 'RHEL 9 must enable auditing of processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

'
  desc 'check', 'Verify that GRUB 2 is configured to enable auditing of processes that start prior to the audit daemon with the following commands:

Check that the current GRUB 2 configuration enabled auditing:

$ sudo grubby --info=ALL | grep audit

args="ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 pti=on 

If "audit" is not set to "1" or is missing, this is a finding.

Check that auditing is enabled by default to persist in kernel updates: 

$ sudo grep audit /etc/default/grub

GRUB_CMDLINE_LINUX="audit=1"

If "audit" is not set to "1", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Enable auditing of processes that start prior to the audit daemon with the following command:

$ sudo grubby --update-kernel=ALL --args="audit=1"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="audit=1"'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61537r925373_chk'
  tag severity: 'low'
  tag gid: 'V-257796'
  tag rid: 'SV-257796r925375_rule'
  tag stig_id: 'RHEL-09-212055'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-61461r925374_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000254-GPOS-00095']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001464', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AU-14 (1)', 'MA-4 (1) (a)']
end
