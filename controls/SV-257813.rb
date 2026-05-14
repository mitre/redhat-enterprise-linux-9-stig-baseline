control 'SV-257813' do
  title 'RHEL 9 must disable storing core dumps.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers or system operators trying to debug problems. Enabling core dumps on production systems is not recommended; however, there may be overriding operational requirements to enable advanced debugging. Permitting temporary enablement of core dumps during such situations must be reviewed through local needs and policy.'
  desc 'check', 'Note: If kernel dumps are disabled in accordance with RHEL-09-213040, this requirement is not applicable.

Verify RHEL 9 disables storing core dumps for all users by issuing the following command:

$ grep -i storage /etc/systemd/coredump.conf

Storage=none

If the "Storage" item is missing or commented out, or the value is anything other than "none", and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the "core" item assigned, this is a finding.'
  desc 'fix', 'Configure the operating system to disable storing core dumps for all users.

Add or modify the following line in /etc/systemd/coredump.conf:

Storage=none'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257813'
  tag rid: 'SV-257813r1134899_rule'
  tag stig_id: 'RHEL-09-213090'
  tag fix_id: 'F-61478r925425_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
  }

  if input('storing_core_dumps_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe parse_config_file('/etc/systemd/coredump.conf') do
      its('Coredump.Storage') { should cmp 'none' }
    end
  end
end
