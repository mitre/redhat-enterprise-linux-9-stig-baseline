control 'SV-258040' do
  title 'RHEL 9 wireless network adapters must be disabled.'
  desc 'This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 9 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice and pointing devices, and near field communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the Authorizing Official (AO). Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 9 operating system.

'
  desc 'check', 'Verify there are no wireless interfaces configured on the system with the following command:

Note: This requirement is Not Applicable for systems that do not have physical wireless network radios.

$ nmcli device status

DEVICE                    TYPE            STATE                    CONNECTION
virbr0                      bridge         connected             virbr0
wlp7s0                    wifi              connected            wifiSSID
enp6s0                    ethernet     disconnected        --
p2p-dev-wlp7s0     wifi-p2p     disconnected        --
lo                             loopback    unmanaged           --
virbr0-nic                tun              unmanaged          --

If a wireless interface is configured and has not been documented and approved by the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces with the following command:

$ nmcli radio all off'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61781r926105_chk'
  tag severity: 'medium'
  tag gid: 'V-258040'
  tag rid: 'SV-258040r926107_rule'
  tag stig_id: 'RHEL-09-291040'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-61705r926106_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000481-GPOS-00481']
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418', 'CCI-002421']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8', 'SC-8 (1)']
end
