control 'SV-257839' do
  title 'RHEL 9 must have the gnutls-utils package installed.'
  desc 'GnuTLS is a secure communications library implementing the SSL, TLS and DTLS protocols and technologies around them. It provides a simple C language application programming interface (API) to access the secure communications protocols as well as APIs to parse and write X.509, PKCS #12, OpenPGP and other required structures. This package contains command line TLS client and server and certificate manipulation tools.'
  desc 'check', 'Verify that RHEL 9 has the gnutls-utils package installed with the following command:

$ dnf list --installed gnutls-utils

Example output:

gnutls-utils.x86_64          3.7.3-9.el9

If the "gnutls-utils" package is not installed, this is a finding.'
  desc 'fix', 'The gnutls-utils package can be installed with the following command:
 
$ sudo dnf install gnutls-utils'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61580r925502_chk'
  tag severity: 'medium'
  tag gid: 'V-257839'
  tag rid: 'SV-257839r925504_rule'
  tag stig_id: 'RHEL-09-215080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61504r925503_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
