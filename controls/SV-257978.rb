control 'SV-257978' do
  title 'All RHEL 8 networked systems must have SSH installed.'
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
not have to be employed, and vice versa.'
  desc 'check', 'Verify SSH is installed with the following command:

$ sudo yum list installed openssh-server

openssh-server.x86_64                 8.0p1-5.el8          @anaconda

If the "SSH server" package is not installed, this is a finding.'
  desc 'fix', 'Install SSH packages onto the host with the following command:

$ sudo yum install openssh-server.x86_64'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-244549'
  tag rid: 'SV-257978r916422_rule'
  tag stig_id: 'RHEL-08-040159'
  tag fix_id: 'F-47781r743895_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
  tag 'host'
  tag 'container-conditional'

  openssh_present = package('openssh-server').installed?

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !openssh_present)
  }

  if input('allow_container_openssh_server') == false
    describe 'In a container Environment' do
      it 'the OpenSSH Server should be installed only when allowed in a container environment' do
        expect(openssh_present).to eq(false), 'OpenSSH Server is installed but not approved for the container environment'
      end
    end
  else
    describe 'In a machine environment' do
      it 'the OpenSSH Server should be installed' do
        expect(package('openssh-server').installed?).to eq(true), 'the OpenSSH Server is not installed'
      end
    end
  end
end
