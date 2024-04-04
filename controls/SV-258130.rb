control 'SV-258130' do
  title 'RHEL 8 must prevent system daemons from using Kerberos for
authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    The key derivation function (KDF) in Kerberos is not FIPS compatible.
Ensuring the system does not have any keytab files present prevents system
daemons from using Kerberos for authentication.  A keytab is a file containing
pairs of Kerberos principals and encrypted keys.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.'
  desc 'check', 'Verify that RHEL 8 prevents system daemons from using Kerberos for
authentication.

    If the system is a server utilizing krb5-server-1.17-18.el8.x86_64 or
newer, this requirement is not applicable.
    If the system is a workstation utilizing
krb5-workstation-1.17-18.el8.x86_64 or newer, this requirement is not
applicable.

    Check if there are available keytabs with the following command:

    $ sudo ls -al /etc/*.keytab

    If this command produces any file(s), this is a finding.'
  desc 'fix', 'Configure RHEL 8 to prevent system daemons from using Kerberos for
authentication.

    Remove any files with the .keytab extension from the operating system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-230238'
  tag rid: 'SV-258130r646862_rule'
  tag stig_id: 'RHEL-08-010161'
  tag fix_id: 'F-32882r567461_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
  tag 'host'
  tag 'container'

  krb5_server = package('krb5-server')
  krb5_workstation = package('krb5-workstation')

  if (krb5_server.installed? && krb5_server.version >= '1.17-18.el8') || (krb5_workstation.installed? && krb5_workstation.version >= '1.17-18.el8')
    impact 0.0
    describe 'The system has krb5-workstation and server version 1.17-18 or higher' do
      skip 'The system has krb5-workstation and server version 1.17-18 or higner, this requirement is Not Applicable.'
    end
  else
    keytabs = command('ls /etc/*.keytab').stdout.split
    describe 'The system' do
      it 'should not have keytab files for Kerberos' do
        expect(keytabs).to be_empty, "Keytab files:\n\t- #{keytabs.join("\n\t- ")}"
      end
    end
  end
end
