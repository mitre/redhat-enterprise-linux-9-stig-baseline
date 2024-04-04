control 'SV-257994' do
  title 'RHEL 8 must force a frequent session key renegotiation for SSH
connections to the server.'
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

$ sudo grep -ir RekeyLimit /etc/ssh/sshd_config*

RekeyLimit 1G 1h

If "RekeyLimit" does not have a maximum data amount and maximum time defined, is missing or commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the system to force a frequent session key renegotiation for SSH
connections to the server by add or modifying the following line in the
"/etc/ssh/sshd_config" file:

    RekeyLimit 1G 1h

    Restart the SSH daemon for the settings to take effect.

    $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000420-GPOS-00186', 'SRG-OS-000424-GPOS-00188']
  tag gid: 'V-230527'
  tag rid: 'SV-257994r877398_rule'
  tag stig_id: 'RHEL-08-040161'
  tag fix_id: 'F-33171r568328_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers without SSH enabled', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('RekeyLimit') { should cmp '1G 1h' }
  end
end
