control 'SV-258139' do
  title 'RHEL 9 must be configured so that the file integrity tool verifies extended attributes.'
  desc 'RHEL 9 installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.'
  desc 'check', 'Verify that AIDE is configured to verify extended attributes with the following command:

$ sudo grep xattrs /etc/aide.conf

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

If the "xattrs" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or extended attributes are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to check file and directory extended
attributes.

    If AIDE is installed, ensure the "xattrs" rule is present on all
uncommented file and directory selection lists.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258139'
  tag rid: 'SV-258139r1045276_rule'
  tag stig_id: 'RHEL-09-651035'
  tag fix_id: 'F-61804r926403_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe package('aide') do
    it { should be_installed }
  end

  findings = []
  aide_conf.where { !selection_line.start_with? '!' }.entries.each do |selection|
    findings.append(selection.selection_line) unless selection.rules.include? 'xattrs'
  end

  describe "List of monitored files/directories without 'xattrs' rule" do
    subject { findings }
    it { should be_empty }
  end
end
