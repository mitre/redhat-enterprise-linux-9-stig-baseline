control 'SV-257847' do
  title 'RHEL 9 must use a separate file system for the system audit data path.'
  desc 'Placing "/var/log/audit" in its own partition enables better separation between audit files and other system files, and helps ensure that auditing cannot be halted due to the partition running out of space.'
  desc 'check', 'Verify that a separate file system/partition has been created for the system audit data path with the following command:

Note: /var/log/audit is used as the example as it is a common location.

$ mount | grep /var/log/audit

UUID=2efb2979-45ac-82d7-0ae632d11f51 on /var/log/home type xfs  (rw,realtime,seclabel,attr2,inode64)

If no line is returned, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-257847'
  tag rid: 'SV-257847r925528_rule'
  tag stig_id: 'RHEL-09-231030'
  tag fix_id: 'F-61512r925527_fix'
  tag cci: ['CCI-000366', 'CCI-001849']
  tag nist: ['CM-6 b', 'AU-4']
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
