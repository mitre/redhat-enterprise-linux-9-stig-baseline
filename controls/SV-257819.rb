control 'SV-257819' do
  title 'RHEL 8 must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Red Hat cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.'
  desc 'check', 'Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For RHEL 8 software packages, Red Hat uses GPG keys labeled "release key 2" and "auxiliary key 2". The keys are defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" by default.

List Red Hat GPG keys installed on the system:

     $ sudo rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "red hat"

     gpg(Red Hat, Inc. (release key 2) <security@redhat.com>)
     gpg(Red Hat, Inc. (auxiliary key) <security@redhat.com>)

If Red Hat GPG keys "release key 2" and "auxiliary key 2" are not installed, this is a finding.

Note: The "auxiliary key 2" appears as "auxiliary key" on a RHEL 8 system.

List key fingerprints of installed Red Hat GPG keys:

     $ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

If key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" is missing, this is a finding.

Example output:

     pub   rsa4096/FD431D51 2009-10-22 [SC]
           Key fingerprint = 567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51
     uid                   Red Hat, Inc. (release key 2) <security@redhat.com>
     pub   rsa4096/D4082792 2018-06-27 [SC]
           Key fingerprint = 6A6A A7C9 7C88 90AE C6AE  BFE2 F76F 66C3 D408 2792
     uid                   Red Hat, Inc. (auxiliary key) <security@redhat.com>
     sub   rsa4096/1B5584D3 2018-06-27 [E]

Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed for RHEL 8 on Red Hat "Product Signing Keys" webpage at https://access.redhat.com/security/team/key.

If key fingerprints do not match, this is a finding.'
  desc 'fix', 'Install Red Hat package-signing keys on the system and verify their fingerprints match vendor values.

Insert RHEL 8 installation disc or attach RHEL 8 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy Red Hat GPG key file onto the system:

     $ sudo cp /media/cdrom/RPM-GPG-KEY-redhat-release /etc/pki/rpm-gpg/

Import Red Hat GPG keys from key file into system keyring:

     $ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

Using the steps listed in the Check Text, confirm the newly imported keys show as installed on the system and verify their fingerprints match vendor values.'
  impact 0.5
  tag check_id: 'C-60651r902750_chk'
  tag severity: 'medium'
  tag gid: 'V-256973'
  tag rid: 'SV-257819r902752_rule'
  tag stig_id: 'RHEL-08-010019'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60593r902751_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
  tag 'host'
  tag 'container'

  rpm_gpg_file = input('rpm_gpg_file')
  rpm_gpg_keys = input('rpm_gpg_keys')

  describe file(rpm_gpg_file) do
    it { should exist }
  end
  rpm_gpg_keys.each do |k, v|
    describe command('rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "red hat"') do
      its('stdout') { should include k.to_s }
    end
    next unless file(rpm_gpg_file).exist?

    describe command("gpg -q --keyid-format short --with-fingerprint #{rpm_gpg_file}") do
      its('stdout') { should include v }
    end
  end
end
