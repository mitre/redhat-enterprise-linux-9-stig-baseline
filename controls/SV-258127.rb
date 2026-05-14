control 'SV-258127' do
  title 'RHEL 9, for PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and nonrepudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Verify the SSH private key files have a passcode.

For each private key stored on the system, use the following command:

$ sudo ssh-keygen -y -f /path/to/file

The expected output is a password prompt:
 "Enter passphrase:"

If the password prompt is not displayed, and the contents of the key are displayed, this is a finding.'
  desc 'fix', 'Create a new private and public key pair that utilizes a passcode with the following command:

$ sudo ssh-keygen -N [passphrase]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag gid: 'V-258127'
  tag rid: 'SV-258127r1155648_rule'
  tag stig_id: 'RHEL-09-611190'
  tag fix_id: 'F-61792r1155647_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)', 'IA-5 (2) (a) (1)']
  tag 'host'

  if %w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
    impact 0.0
    describe 'N/A' do
      skip 'Control not applicable within a container'
    end
  elsif input('private_key_files').empty?
    impact 0.0
    describe 'N/A' do
      skip 'No private key files were given in the input; this control is Not Applicable'
    end
  elsif input('private_key_files').map { |kf| file(kf).exist? }.uniq.first == false
    describe 'no files found' do
      skip 'No private key files given in the input were found on the system; check that the input accurately lists all private keys on this system'
    end
  elsif !input('alternate_mfa_method').to_s.empty?
    impact 0.0
    describe 'N/A' do
      skip 'The system is using an approved alternative MFA method; this control is Not Applicable.'
    end
  else
    passwordless_keys = input('private_key_files').select { |kf|
      file(kf).exist? &&
        !inspec.command("ssh-keygen -y -P '' -f #{kf}").stderr.match('incorrect passphrase supplied to decrypt private key')
    }
    describe 'Private key files' do
      it 'should all have passwords set' do
        expect(passwordless_keys).to be_empty, "Passwordless key files:\n\t- #{passwordless_keys.join("\n\t- ")}"
      end
    end
  end
end
