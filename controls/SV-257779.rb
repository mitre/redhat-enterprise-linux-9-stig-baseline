control 'SV-257779' do
  title 'RHEL 8 must display the Standard Mandatory DoD Notice and Consent
Banner before granting local or remote access to the system via a command line
user logon.'
  desc 'Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."'
  desc 'check', 'Verify RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner
before granting access to the operating system via a command line user logon.

    Check that RHEL 8 displays a banner at the command line login screen with
the following command:

    $ sudo cat /etc/issue

    If the banner is set correctly it will return the following text:

    “You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.”

    If the banner text does not match the Standard Mandatory DoD Notice and
Consent Banner exactly, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to display the Standard Mandatory DoD Notice and Consent
Banner before granting access to the system via command line logon.

    Edit the "/etc/issue" file to replace the default text with the Standard
Mandatory DoD Notice and Consent Banner. The DoD-required text is:

    "You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests -- not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details."'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-230227'
  tag rid: 'SV-257779r627750_rule'
  tag stig_id: 'RHEL-08-010060'
  tag fix_id: 'F-32871r567428_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  banner_file = file('/etc/issue')

  describe banner_file do
    it { should exist }
  end

  if banner_file.exist?

    banner = banner_file.content.gsub(/[\r\n\s]/, '')
    expected_banner = input('banner_message_text_cli').gsub(/[\r\n\s]/, '')

    describe 'The CLI Login Banner ' do
      it 'is set to the standard banner and has the correct text' do
        expect(banner).to eq(expected_banner), 'Banner does not match expected text'
      end
    end
  end
end
