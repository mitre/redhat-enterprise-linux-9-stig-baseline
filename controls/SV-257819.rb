control 'SV-257819' do
  title 'RHEL 9 must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Red Hat cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.'
  desc 'check', 'Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For RHEL 9 software packages, Red Hat uses GPG keys labeled "release key 2" and "auxiliary key 3". The keys are defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" by default.

List Red Hat GPG keys installed on the system:

$ sudo rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "red hat"

Red Hat, Inc. (release key 2) <security@redhat.com> public key
Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key

If Red Hat GPG keys "release key 2" and "auxiliary key 3" are not installed, this is a finding.

List key fingerprints of installed Red Hat GPG keys:

$ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

If key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" is missing, this is a finding.

Example output:

pub   rsa4096/FD431D51 2009-10-22 [SC]
      Key fingerprint = 567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51
uid                   Red Hat, Inc. (release key 2) <security@redhat.com>
pub   rsa4096/5A6340B3 2022-03-09 [SC]
      Key fingerprint = 7E46 2425 8C40 6535 D56D  6F13 5054 E4A4 5A63 40B3
uid                   Red Hat, Inc. (auxiliary key 3) <security@redhat.com>

Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed for RHEL 9 on Red Hat "Product Signing Keys" webpage at https://access.redhat.com/security/team/key.

If key fingerprints do not match, this is a finding.'
  desc 'fix', 'Install Red Hat package-signing keys on the system and verify their fingerprints match vendor values.

Insert RHEL 9 installation disc or attach RHEL 9 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy Red Hat GPG key file onto the system:

$ sudo cp /media/cdrom/RPM-GPG-KEY-redhat-release /etc/pki/rpm-gpg/

Import Red Hat GPG keys from key file into system keyring:

$ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

Using the steps listed in the Check Text, confirm the newly imported keys show as installed on the system and verify their fingerprints match vendor values.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61560r925442_chk'
  tag severity: 'medium'
  tag gid: 'V-257819'
  tag rid: 'SV-257819r925444_rule'
  tag stig_id: 'RHEL-09-214010'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-61484r925443_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe file('/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release') do
    it { should exist }
  end
end
