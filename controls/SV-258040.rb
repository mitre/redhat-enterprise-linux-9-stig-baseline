control 'SV-258040' do
  title 'RHEL 8 wireless network adapters must be disabled.'
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
  desc 'check', 'Verify there are no wireless interfaces configured on the system with the
following command:

    Note: This requirement is Not Applicable for systems that do not have
physical wireless network radios.

    $ sudo nmcli device status

    DEVICE                    TYPE            STATE
CONNECTION
    virbr0                      bridge         connected             virbr0
    wlp7s0                    wifi              connected            wifiSSID
    enp6s0                    ethernet     disconnected        --
    p2p-dev-wlp7s0     wifi-p2p     disconnected        --
    lo                             loopback    unmanaged           --
    virbr0-nic                tun              unmanaged          --

    If a wireless interface is configured and has not been documented and
approved by the Information System Security Officer (ISSO), this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces with the
following command:

    $ sudo nmcli radio all off'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000481-GPOS-000481']
  tag gid: 'V-230506'
  tag rid: 'SV-258040r627750_rule'
  tag stig_id: 'RHEL-08-040110'
  tag fix_id: 'F-33150r568265_fix'
  tag cci: ['CCI-001444']
  tag nist: ['AC-18 (1)']
  tag 'host'
  tag 'container'

  if input('wifi_hardware')
    describe command('nmcli device') do
      its('stdout.strip') { should_not match(/wifi\s*connected/) }
    end
  else
    impact 0.0
    describe 'Skip' do
      skip 'The system does not have a wireless network adapter, this control is Not Applicable.'
    end
  end
end
