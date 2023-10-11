control 'SV-258036' do
  title 'RHEL 9 must have the USBGuard package enabled.'
  desc 'The USBguard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the usbguard-rules.conf file. The policy and the authorization state of USB devices can be modified during runtime using the usbguard tool.

The system administrator (SA) must work with the site information system security officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.'
  desc 'check', 'Verify RHEL 9 has USBGuard enabled with the following command:

$ systemctl is-active usbguard

active

If usbguard is not active, ask the SA to indicate how unauthorized peripherals are being blocked.

If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.'
  desc 'fix', 'To enable the USBGuard service run the following command:

$ sudo systemctl enable --now usbguard'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61777r926093_chk'
  tag severity: 'medium'
  tag gid: 'V-258036'
  tag rid: 'SV-258036r926095_rule'
  tag stig_id: 'RHEL-09-291020'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-61701r926094_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
