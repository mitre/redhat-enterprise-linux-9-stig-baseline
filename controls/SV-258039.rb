control 'SV-258039' do
  title 'RHEL 8 Bluetooth must be disabled.'
  desc 'Without protection of communications with wireless peripherals,
confidentiality and integrity may be compromised because unprotected
communications can be intercepted and either read, altered, or used to
compromise the RHEL 8 operating system.

    This requirement applies to wireless peripheral technologies (e.g.,
wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless
peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and
Near Field Communications [NFC]) present a unique challenge by creating an
open, unsecured port on a computer. Wireless peripherals must meet DoD
requirements for wireless data transmission and be approved for use by the
Authorizing Official (AO). Even though some wireless peripherals, such as mice
and pointing devices, do not ordinarily carry information that need to be
protected, modification of communications with these wireless peripherals may
be used to compromise the RHEL 8 operating system. Communication paths outside
the physical protection of a controlled boundary are exposed to the possibility
of interception and modification.

    Protecting the confidentiality and integrity of communications with
wireless peripherals can be accomplished by physical means (e.g., employing
physical barriers to wireless radio frequencies) or by logical means (e.g.,
employing cryptographic techniques). If physical means of protection are
employed, then logical means (cryptography) do not have to be employed, and
vice versa. If the wireless peripheral is only passing telemetry data,
encryption of the data may not be required.'
  desc 'check', 'If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of Bluetooth is a local AO decision.

Determine if Bluetooth is disabled with the following command:

     $ sudo grep bluetooth /etc/modprobe.d/*
     /etc/modprobe.d/bluetooth.conf:install bluetooth /bin/false

If the Bluetooth driver blacklist entry is missing, a Bluetooth driver is determined to be in use, and the collaborative computing device has not been authorized for use, this is a finding.

Verify the operating system disables the ability to use Bluetooth with the following command:

     $ sudo grep -r bluetooth /etc/modprobe.d | grep -i "blacklist" | grep -v "^#"
     blacklist bluetooth

If the command does not return any output or the output is not "blacklist bluetooth", and use of Bluetooth is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the Bluetooth adapter when not in use.

Build or modify the "/etc/modprobe.d/bluetooth.conf" file with the following line:

     install bluetooth /bin/false

Disable the ability to use the Bluetooth kernel module.

     $ sudo vi /etc/modprobe.d/blacklist.conf

Add or update the line:

     blacklist bluetooth

Reboot the system for the settings to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000300-GPOS-00118'
  tag gid: 'V-230507'
  tag rid: 'SV-258039r942939_rule'
  tag stig_id: 'RHEL-08-040111'
  tag fix_id: 'F-33151r942938_fix'
  tag cci: ['CCI-001443']
  tag nist: ['AC-18 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('bluetooth_installed')
    describe kernel_module('bluetooth') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  else
    impact 0.0
    describe 'Device or operating system does not have a Bluetooth adapter installed' do
      skip 'If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.'
    end
  end
end
