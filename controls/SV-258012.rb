control 'SV-258012' do
  title 'RHEL 8 must display a banner before granting local or remote access to
the system via a graphical user logon.'
  desc 'Display of a standardized and approved use notification before
granting access to the operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.'
  desc 'check', 'Verify RHEL 8 displays a banner before granting access to the operating
system via a graphical user logon.

    Note: This requirement assumes the use of the RHEL 8 default graphical user
interface, Gnome Shell. If the system does not have any graphical user
interface installed, this requirement is Not Applicable.

    Check to see if the operating system displays a banner at the logon screen
with the following command:

    $ sudo grep banner-message-enable /etc/dconf/db/local.d/*

    banner-message-enable=true

    If "banner-message-enable" is set to "false" or is missing, this is a
finding.'
  desc 'fix', 'Configure the operating system to display a banner before granting access
to the system.

    Note: If the system does not have a graphical user interface installed,
this requirement is Not Applicable.

    Create a database to contain the system-wide graphical user logon settings
(if it does not already exist) with the following command:

    $ sudo touch /etc/dconf/db/local.d/01-banner-message

    Add the following lines to the [org/gnome/login-screen] section of the
"/etc/dconf/db/local.d/01-banner-message":

    [org/gnome/login-screen]

    banner-message-enable=true

    Run the following command to update the database:

    $ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-244519'
  tag rid: 'SV-258012r743806_rule'
  tag stig_id: 'RHEL-08-010049'
  tag fix_id: 'F-47751r743805_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed, this control is Not Applicable' do
      skip 'A GUI desktop is not installed, this control is Not Applicable.'
    end
  else
    describe command('grep ^banner-message-enable /etc/dconf/db/local.d/*') do
      its('stdout.strip') { should cmp 'banner-message-enable=true' }
    end
  end
end
