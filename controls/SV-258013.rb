control 'SV-258013' do
  title 'RHEL 9 must prevent a user from overriding the banner-message-enable setting for the graphical user interface.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

For U.S. Government systems, system use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 prevents a user from overriding settings for graphical user interfaces. 

Determine if the org.gnome.login-screen banner-message-enable key is writable with the following command:
	
$ gsettings writable org.gnome.login-screen banner-message-enable
	 
false
	 
If "banner-message-enable" is writable or the result is "true", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding the banner setting for graphical user interfaces. 

Create a database to contain the systemwide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following setting to prevent nonprivileged users from modifying it:

/org/gnome/login-screen/banner-message-enable

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61754r1045080_chk'
  tag severity: 'medium'
  tag gid: 'V-258013'
  tag rid: 'SV-258013r1045082_rule'
  tag stig_id: 'RHEL-09-271015'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-61678r1045081_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
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

    profile = command('grep system-db /etc/dconf/profile/user').stdout.strip.match(/:(\S+)$/)[1]

    describe command("grep ^banner-message-enable /etc/dconf/db/#{profile}.d/*") do
      its('stdout.strip') { should match(%r{^/org/gnome/login-screen/banner-message-enable}) }
    end
  end
end
