control 'SV-258012' do
  title 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

For U.S. Government systems, system use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.'
  desc 'check', 'Verify RHEL 9 displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine if the operating system displays a banner at the logon screen with the following command:

$ gsettings get org.gnome.login-screen banner-message-enable

true

If the result is "false", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via a graphical user logon.

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/01-banner-message

Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

[org/gnome/login-screen]

banner-message-enable=true

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-258012'
  tag rid: 'SV-258012r1014855_rule'
  tag stig_id: 'RHEL-09-271010'
  tag fix_id: 'F-61677r926022_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('banner-message-enable', 'org.gnome.login-screen')

  if g.has_gui?
    if g.has_gnome_gui?
      if g.has_non_gnome_gui?
        if !gs.exist? || !gs.set?('true')
          describe gs do
            it 'should exist.' do
              expect(subject).to exist, "#{subject} must be set using either `gsettings set` or modifying the `gconf` keyfiles and regenerating the `gconf` databases.  Received the following error on access: `#{subject.get.stderr.strip}`."
            end
            it 'should be true.' do
              expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases."
            end
          end
        end
        describe 'Non-GNOME desktop environments detected' do
          skip "Manual check required.  There is no guidance for non-GNOME desktop environments.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
        end
      else
        describe gs do
          it 'should exist.' do
            expect(subject).to exist, "#{subject} must be set using either `gsettings set` or modifying the `gconf` keyfiles and regenerating the `gconf` databases.  Received the following error on access: `#{subject.get.stderr.strip}`."
          end
          it 'should be true.' do
            expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases."
          end
        end
      end
    else
      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required.  There is no guidance for non-GNOME desktop environments.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_guis.join("\n\t- ")}"
      end
    end
  else
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  end
end
