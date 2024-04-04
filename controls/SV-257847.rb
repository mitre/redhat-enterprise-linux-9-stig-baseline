control 'SV-257847' do
  title 'RHEL 8 must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for the
system audit data path with the following command:

    Note: /var/log/audit is used as the example as it is a common location.

    $ sudo grep /var/log/audit /etc/fstab

    UUID=3645951a /var/log/audit xfs defaults 1 2

    If an entry for "/var/log/audit" does not exist, ask the System
Administrator if the system audit logs are being written to a different file
system/partition on the system, then grep for that file system/partition.

    If a separate file system/partition does not exist for the system audit
data path, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230294'
  tag rid: 'SV-257847r627750_rule'
  tag stig_id: 'RHEL-08-010542'
  tag fix_id: 'F-32938r567629_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_data_path = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe mount(audit_data_path) do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == audit_data_path } do
    it { should exist }
  end
end
