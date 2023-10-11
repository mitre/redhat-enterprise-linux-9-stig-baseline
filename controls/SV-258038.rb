control 'SV-258038' do
  title 'RHEL 9 must block unauthorized peripherals before establishing a connection.'
  desc 'The USBguard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the usbguard-rules.conf file. The policy and the authorization state of USB devices can be modified during runtime using the usbguard tool.

The system administrator (SA) must work with the site information system security officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.'
  desc 'check', 'Verify the USBGuard has a policy configured with the following command:

$ usbguard list-rules

allow id 1d6b:0001 serial

If the command does not return results or an error is returned, ask the SA to indicate how unauthorized peripherals are being blocked.

If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the operating system to enable the blocking of unauthorized peripherals with the following command:

Note: This command must be run from a root shell and will create an allow list for any usb devices currently connect to the system.

# usbguard generate-policy --no-hash > /etc/usbguard/rules.conf

Note: Enabling and starting usbguard without properly configuring it for an individual system will immediately prevent any access over a usb device such as a keyboard or mouse.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61779r926099_chk'
  tag severity: 'medium'
  tag gid: 'V-258038'
  tag rid: 'SV-258038r926101_rule'
  tag stig_id: 'RHEL-09-291030'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-61703r926100_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
