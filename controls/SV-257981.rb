control 'SV-257981' do
  title 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.'
  desc 'The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.'
  desc 'check', 'Verify any SSH connection to the operating system displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system.

Check for the location of the banner file being used with the following command:

$ sudo grep -ir banner /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

banner /etc/issue

This command will return the banner keyword and the name of the file that contains the SSH banner (in this case "/etc/issue").

If the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via ssh.

Edit the "/etc/ssh/sshd_config" file to uncomment the banner keyword and configure it to point to a file that will contain the logon banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

An example configuration line is:

Banner /etc/issue'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-257981'
  tag rid: 'SV-257981r943028_rule'
  tag stig_id: 'RHEL-09-255025'
  tag fix_id: 'F-61646r925929_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !virtualization.system.eql?('docker') || file('/etc/ssh/sshd_config').exist?
  }

  # When Banner is commented, not found, disabled, or the specified file does not exist, this is a finding.
  banner_file = sshd_config.banner

  # Banner property is commented out.
  if banner_file.nil?
    describe 'The SSHD Banner is not set' do
      subject { banner_file.nil? }
      it { should be false }
    end
  end

  # Banner property is set to "none"
  if !banner_file.nil? && !banner_file.match(/none/i).nil?
    describe 'The SSHD Banner is disabled' do
      subject { banner_file.match(/none/i).nil? }
      it { should be true }
    end
  end

  # Banner property provides a path to a file, however, it does not exist.
  if !banner_file.nil? && banner_file.match(/none/i).nil? && !file(banner_file).exist?
    describe 'The SSHD Banner is set, but, the file does not exist' do
      subject { file(banner_file).exist? }
      it { should be true }
    end
  end

  # Banner property provides a path to a file and it exists.
  next unless !banner_file.nil? && banner_file.match(/none/i).nil? && file(banner_file).exist?

  banner = file(banner_file).content.gsub(/[\r\n\s]/, '')
  expected_banner = input('banner_message_text_ral').gsub(/[\r\n\s]/, '')

  describe 'The SSHD Banner' do
    it 'is set to the standard banner and has the correct text' do
      expect(banner).to eq(expected_banner), 'Banner does not match expected text'
    end
  end
end
