control 'SV-258173' do
  title 'RHEL 8 must allocate an audit_backlog_limit of sufficient size to
capture processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some
startup processes may not be audited. Some audit systems also maintain state
information only available if auditing is enabled before a given process is
created.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    Allocating an audit_backlog_limit of sufficient size is critical in
maintaining a stable boot process.  With an insufficient limit allocated, the
system is susceptible to boot failures and crashes.'
  desc 'check', 'Verify RHEL 8 allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following commands:

$ sudo grub2-editenv list | grep audit

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the "audit_backlog_limit" entry does not equal "8192" or greater, is missing, or the line is commented out, this is a finding.

Check the audit_backlog_limit is set to persist in kernel updates:

$ sudo grep audit /etc/default/grub

GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"

If "audit_backlog_limit" is not set to "8192" or greater, is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to allocate sufficient audit_backlog_limit to capture
processes that start prior to the audit daemon with the following command:

    $ sudo grubby --update-kernel=ALL --args="audit_backlog_limit=8192"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-230469'
  tag rid: 'SV-258173r877391_rule'
  tag stig_id: 'RHEL-08-030602'
  tag fix_id: 'F-33113r568154_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_config = command('grub2-editenv - list').stdout
  kernelopts = parse_config(grub_config)['kernelopts'].strip.gsub(' ', "\n")
  grub_cmdline_linux = parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX'].strip.gsub(' ', "\n").gsub('"',
                                                                                                               '')

  expected_backlog_limit = input('expected_backlog_limit')

  describe 'kernelopts' do
    subject { parse_config(kernelopts) }
    its('audit_backlog_limit') { should cmp >= expected_backlog_limit }
  end

  describe 'persistant kernelopts' do
    subject { parse_config(grub_cmdline_linux) }
    its('audit_backlog_limit') { should cmp >= expected_backlog_limit }
  end
end
