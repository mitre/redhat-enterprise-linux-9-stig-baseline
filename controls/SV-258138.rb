control 'SV-258138' do
  title 'RHEL 9 must be configured so that the file integrity tool verifies Access Control Lists (ACLs).'
  desc 'RHEL 9 installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

ACLs can provide permissions beyond those permitted through the file mode and must be verified by the file integrity tools.'
  desc 'check', 'Verify that that AIDE is verifying ACLs with the following command:

$ grep acl /etc/aide.conf

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

If the "acl" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or ACLs are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to check file and directory ACLs.

If AIDE is installed, ensure the "acl" rule is present on all uncommented file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258138'
  tag rid: 'SV-258138r926401_rule'
  tag stig_id: 'RHEL-09-651030'
  tag fix_id: 'F-61803r926400_fix'
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
    findings.append(selection.selection_line) unless selection.rules.include? 'acl'
  end

  describe "List of monitored files/directories without 'acl' rule" do
    subject { findings }
    it { should be_empty }
  end
end
