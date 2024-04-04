control 'SV-257994' do
  title 'RHEL 9 must force a frequent session key renegotiation for SSH connections to the server.'
  desc 'Without protection of the transmitted information, confidentiality and
integrity may be compromised because unprotected communications can be
intercepted and either read or altered.

    This requirement applies to both internal and external networks and all
types of information system components from which information can be
transmitted (e.g., servers, mobile devices, notebook computers, printers,
copiers, scanners, and facsimile machines). Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of
interception and modification.

    Protecting the confidentiality and integrity of organizational information
can be accomplished by physical means (e.g., employing physical distribution
systems) or by logical means (e.g., employing cryptographic techniques). If
physical means of protection are employed, then logical means (cryptography) do
not have to be employed, and vice versa.

    Session key regeneration limits the chances of a session key becoming
compromised.'
  desc 'check', 'Verify the SSH server is configured to force frequent session key renegotiation with the following command:

$ sudo grep -ir rekeyLimit /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

RekeyLimit 1G 1h

If "RekeyLimit" does not have a maximum data amount and maximum time defined, is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to force a frequent session key renegotiation for SSH connections to the server by adding or modifying the following line in the "/etc/ssh/sshd_config" file:

RekeyLimit 1G 1h

Restart the SSH daemon for the settings to take effect.

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000420-GPOS-00186', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000423-GPOS-00187']
  tag gid: 'V-257994'
  tag rid: 'SV-257994r943044_rule'
  tag stig_id: 'RHEL-09-255090'
  tag fix_id: 'F-61659r925968_fix'
  tag cci: ['CCI-000068', 'CCI-002418', 'CCI-002421']
  tag nist: ['AC-17 (2)', 'SC-8', 'SC-8 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers without SSH enabled', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('RekeyLimit') { should cmp '1G 1h' }
  end
end
