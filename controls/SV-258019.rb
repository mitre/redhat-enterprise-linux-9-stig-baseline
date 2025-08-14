control 'SV-258019' do
  title 'RHEL 9 must be able to initiate directly a session lock for all connection types using smart card when the smart card is removed.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 9 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.'
  desc 'check', "Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 enables a user's session lock until that user reestablishes access using established identification and authentication procedures with the following command:

$ gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action
 
'lock-screen'
 
If the result is not 'lock-screen', this is a finding."
  desc 'fix', %q(Configure RHEL 9 to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.

Select or create an authselect profile and incorporate the "with-smartcard-lock-on-removal" feature with the following example:

$ sudo authselect select sssd with-smartcard with-smartcard-lock-on-removal

Alternatively, the dconf settings can be edited in the /etc/dconf/db/* location.

Add or update the [org/gnome/settings-daemon/peripherals/smartcard] section of the /etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'

Then update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-258019'
  tag rid: 'SV-258019r1045092_rule'
  tag stig_id: 'RHEL-09-271045'
  tag fix_id: 'F-61684r926043_fix'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000057']
  tag nist: ['AC-11 b', 'AC-11 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if !input('smart_card_enabled')
    impact 0.0
    describe "The system is not smartcard enabled thus this control is Not
    Applicable" do
      skip "The system is not using Smartcards / PIVs to fulfil the MFA
      requirement, this control is Not Applicable."
    end
  elsif !package('gnome-desktop3').installed?
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
      Applicable."
    end
  else
    output = command('gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action').stdout.strip
    describe 'Smart card removal should trigger a session lock until reauthentication' do
      subject { output }
      it { should cmp "'lock-screen'" }
    end
  end
end
