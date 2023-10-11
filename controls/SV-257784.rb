control 'SV-257784' do
  title 'The systemd Ctrl-Alt-Delete burst key sequence in RHEL 9 must be disabled.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

'
  desc 'check', 'Verify RHEL 9 is configured to not reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ grep -i ctrl /etc/systemd/system.conf

CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the system to disable the CtrlAltDelBurstAction by added or modifying the following line in the "/etc/systemd/system.conf" configuration file:

CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61525r925337_chk'
  tag severity: 'high'
  tag gid: 'V-257784'
  tag rid: 'SV-257784r925339_rule'
  tag stig_id: 'RHEL-09-211045'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-61449r925338_fix'
  tag satisfies: ['SRG-OS-000324-GPOS-00125', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002235']
  tag nist: ['CM-6 b', 'AC-6 (10)']
end
