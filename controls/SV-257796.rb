control 'SV-257796' do
  title 'RHEL 8 must enable auditing of processes that start prior to the audit
daemon.'
  desc 'Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some
startup processes may not be audited. Some audit systems also maintain state
information only available if auditing is enabled before a given process is
created.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Verify RHEL 8 enables auditing of processes that start prior to the audit daemon with the following commands:

$ sudo grub2-editenv list | grep audit

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the "audit" entry does not equal "1", is missing, or the line is commented out, this is a finding.

Check that auditing is enabled by default to persist in kernel updates:

$ sudo grep audit /etc/default/grub

GRUB_CMDLINE_LINUX="audit=1"

If "audit" is not set to "1", is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit processes that start prior to the audit daemon
with the following command:

    $ sudo grubby --update-kernel=ALL --args="audit=1"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="audit=1"'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218']
  tag gid: 'V-230468'
  tag rid: 'SV-257796r792904_rule'
  tag stig_id: 'RHEL-08-030601'
  tag fix_id: 'F-33112r568151_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_config = command('grub2-editenv - list').stdout

  describe parse_config(grub_config) do
    its('kernelopts') { should match(/audit=1/) }
  end

  describe parse_config_file('/etc/default/grub') do
    its('GRUB_CMDLINE_LINUX') { should match(/audit=1/) }
  end
end
