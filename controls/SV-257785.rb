control 'SV-257785' do
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 9.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

'
  desc 'check', 'Verify RHEL 9 is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command:

$ sudo systemctl status ctrl-alt-del.target

ctrl-alt-del.target
Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
Active: inactive (dead)

If the "ctrl-alt-del.target" is loaded and not masked, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the ctrl-alt-del.target with the following command:

$ sudo systemctl disable --now ctrl-alt-del.target
$ sudo systemctl mask --now ctrl-alt-del.target'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61526r925340_chk'
  tag severity: 'high'
  tag gid: 'V-257785'
  tag rid: 'SV-257785r925342_rule'
  tag stig_id: 'RHEL-09-211050'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-61450r925341_fix'
  tag satisfies: ['SRG-OS-000324-GPOS-00125', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002235']
  tag nist: ['CM-6 b', 'AC-6 (10)']
end
