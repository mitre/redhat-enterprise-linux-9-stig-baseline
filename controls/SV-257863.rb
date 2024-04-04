control 'SV-257863' do
  title 'RHEL 8 must mount /dev/shm with the nodev option.'
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
  desc 'check', 'Verify "/dev/shm" is mounted with the "nodev" option:

    $ sudo mount | grep /dev/shm

    tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)

    Verify that the "nodev"option is configured for /dev/shm:

    $ sudo cat /etc/fstab | grep /dev/shm

    tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

    If results are returned and the "nodev" option is missing, or if /dev/shm
is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure the system so that /dev/shm is mounted with the "nodev" option
by adding /modifying the /etc/fstab with the following line:

    tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-230508'
  tag rid: 'SV-257863r854049_rule'
  tag stig_id: 'RHEL-08-040120'
  tag fix_id: 'F-33152r568271_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/dev/shm'
  option = 'nodev'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
