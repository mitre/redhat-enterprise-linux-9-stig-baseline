control 'SV-257875' do
  title 'RHEL 8 must mount /var/log/audit with the nosuid option.'
  desc 'The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    The "noexec" mount option causes the system to not execute binary files.
This option must be used for mounting any file system not containing approved
binary files, as they may be incompatible. Executing files from untrusted file
systems increases the opportunity for unprivileged users to attain unauthorized
administrative access.

    The "nodev" mount option causes the system to not interpret character or
block special devices. Executing character or block special devices from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.

    The "nosuid" mount option causes the system to not execute "setuid" and
"setgid" files with owner privileges. This option must be used for mounting
any file system not containing approved "setuid" and "setguid" files.
Executing files from untrusted file systems increases the opportunity for
unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/var/log/audit" is mounted with the "nosuid" option:

    $ sudo mount | grep /var/log/audit

    /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs
(rw,nodev,nosuid,noexec,seclabel)

    Verify that the "nosuid" option is configured for /var/log/audit:

    $ sudo cat /etc/fstab | grep /var/log/audit

    /dev/mapper/rhel-var-log-audit /var/log/audit xfs
defaults,nodev,nosuid,noexec 0 0

    If results are returned and the "nosuid" option is missing, or if
/var/log/audit is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Configure the system so that /var/log/audit is mounted with the "nosuid"
option by adding /modifying the /etc/fstab with the following line:

    /dev/mapper/rhel-var-log-audit /var/log/audit xfs
defaults,nodev,nosuid,noexec 0 0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-230518'
  tag rid: 'SV-257875r854059_rule'
  tag stig_id: 'RHEL-08-040130'
  tag fix_id: 'F-33162r568301_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/var/log/audit'
  option = 'nosuid'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
