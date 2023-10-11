control 'SV-258127' do
  title 'RHEL 9, for PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and nonrepudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Verify the SSH private key files have a passcode.

For each private key stored on the system, use the following command:

$ sudo ssh-keygen -y -f /path/to/file

If the contents of the key are displayed, this is a finding.'
  desc 'fix', 'Create a new private and public key pair that utilizes a passcode with the following command:

$ sudo ssh-keygen -n [passphrase]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61868r926366_chk'
  tag severity: 'medium'
  tag gid: 'V-258127'
  tag rid: 'SV-258127r926368_rule'
  tag stig_id: 'RHEL-09-611190'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-61792r926367_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
