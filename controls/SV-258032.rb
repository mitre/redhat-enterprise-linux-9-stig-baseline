control 'SV-258032' do
  title 'RHEL 9 must prevent a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface.'
  desc 'A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', 'Verify that users cannot enable the Ctrl-Alt-Del sequence in the GNOME desktop with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ grep logout /etc/dconf/db/local.d/locks/* 

/org/gnome/settings-daemon/plugins/media-keys/logout

If the output is not "/org/gnome/settings-daemon/plugins/media-keys/logout", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disallow the user changing the Ctrl-Alt-Del sequence in the GNOME desktop.

Create a database to container system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following line to the session locks file to prevent nonprivileged users from modifying the Ctrl-Alt-Del setting:

/org/gnome/settings-daemon/plugins/media-keys/logout

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61773r926081_chk'
  tag severity: 'medium'
  tag gid: 'V-258032'
  tag rid: 'SV-258032r926083_rule'
  tag stig_id: 'RHEL-09-271110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61697r926082_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
