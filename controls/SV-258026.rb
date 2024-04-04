control 'SV-258026' do
  title 'RHEL 8 must prevent a user from overriding the session lock-delay
setting for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops
work and moves away from the immediate physical vicinity of the information
system but does not log out because of the temporary nature of the absence.
Rather than relying on the user to manually lock their operating system session
prior to vacating the vicinity, operating systems need to be able to identify
when a user's session has idled and take action to initiate the session lock.

    The session lock is implemented at the point where session activity can be
determined and/or controlled.

    Implementing session settings will have little value if a user is able to
manipulate these settings from the defaults prescribed in the other
requirements of this implementation guide.

    Locking these settings from non-privileged users is crucial to maintaining
a protected baseline."
  desc 'check', 'Verify the operating system prevents a user from overriding settings for
graphical user interfaces.

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    Determine which profile the system database is using with the following
command:

    $ sudo grep system-db /etc/dconf/profile/user

    system-db:local

    Check that graphical settings are locked from non-privileged user
modification with the following command:

    Note: The example below is using the database "local" for the system, so
the path is "/etc/dconf/db/local.d". This path must be modified if a database
other than "local" is being used.

    $ sudo grep -i lock-delay /etc/dconf/db/local.d/locks/*

    /org/gnome/desktop/screensaver/lock-delay

    If the command does not return at least the example result, this is a
finding.'
  desc 'fix', 'Configure the operating system to prevent a user from overriding settings
for graphical user interfaces.

    Create a database to contain the system-wide screensaver settings (if it
does not already exist) with the following command:

    Note: The example below is using the database "local" for the system, so
if the system is using another database in "/etc/dconf/profile/user", the
file should be created under the appropriate subdirectory.

    $ sudo touch /etc/dconf/db/local.d/locks/session

    Add the following setting to prevent non-privileged users from modifying it:

    /org/gnome/desktop/screensaver/lock-delay'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-230354'
  tag rid: 'SV-258026r743990_rule'
  tag stig_id: 'RHEL-08-020080'
  tag fix_id: 'F-32998r743989_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if package('gnome-desktop3').installed?
    describe command('grep -i lock-delay /etc/dconf/db/local.d/locks/*') do
      its('stdout.split') { should include '/org/gnome/desktop/screensaver/lock-delay' }
    end
  else
    impact 0.0
    describe 'The GNOME desktop is not installed' do
      skip 'The GNOME desktop is not installed, this control is Not Applicable.'
    end
  end
end
