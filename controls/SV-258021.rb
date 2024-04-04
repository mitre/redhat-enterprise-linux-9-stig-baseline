control 'SV-258021' do
  title 'RHEL 8 must enable a user session lock until that user re-establishes
access using established identification and authentication procedures for
graphical user sessions.'
  desc 'A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined.

    Regardless of where the session lock is determined and implemented, once
invoked, the session lock must remain in place until the user reauthenticates.
No other activity aside from reauthentication must unlock the system.'
  desc 'check', %q(Verify the operating system enables a user's session lock until that user
re-establishes access using established identification and authentication
procedures with the following command:

    $ sudo gsettings get org.gnome.desktop.screensaver lock-enabled

    true

    If the setting is "false", this is a finding.

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.)
  desc 'fix', %q(Configure the operating system to enable a user's session lock until that
user re-establishes access using established identification and authentication
procedures.

    Create a database to contain the system-wide screensaver settings (if it
does not already exist) with the following example:

    $ sudo vi /etc/dconf/db/local.d/00-screensaver

    Edit the "[org/gnome/desktop/screensaver]" section of the database file
and add or update the following lines:

    # Set this to true to lock the screen when the screensaver activates
    lock-enabled=true

    Update the system databases:

    $ sudo dconf update)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-230347'
  tag rid: 'SV-258021r627750_rule'
  tag stig_id: 'RHEL-08-020030'
  tag fix_id: 'F-32991r567788_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if package('gnome-desktop3').installed?
    describe command('gsettings get org.gnome.desktop.screensaver lock-enabled') do
      its('stdout.strip') { should cmp 'true' }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
