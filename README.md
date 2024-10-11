# RedHat Enterprise Linux 9.x Security Technical Implementation Guide InSpec Profile

The Redhat Enterprise Linux 9.X Security Technical Implementation Guide (RHEL9.x STIG) InSpec Profile can help programs automate their compliance checks of RedHat Enterprise Linux 9.x System to Department of Defense (DoD) requirements.

- Profile Version: `1.2.2`
- RedHat Enterprise Linux 9 Security Technical Implementation Guide v1r2

This profile was developed to reduce the time it takes to perform a security checks based upon the STIG Guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA Services Directorate (SD) and the DISA Risk Management Executive (RME) office.

The results of a profile run will provide information needed to support an Authority to Operate (ATO) decision for the applicable technology.

The RHEL8 STIG Profile uses the [InSpec](https://github.com/inspec/inspec) open-source compliance validation language to support automation of the required compliance, security and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================

* [RedHat Enterprise Linux 9.x Security Technical Implementation Guide InSpec Profile](#redhat-enterprise-linux-9x-security-technical-implementation-guide-inspec-profile)
   * [RedHat 9.x Enterprise Linux Security Technical Implementation Guide (RHEL9 STIG)](#redhat-9x-enterprise-linux-security-technical-implementation-guide-rhel9-stig)
* [Getting Started and Intended Usage](#getting-started-and-intended-usage)
   * [Intended Usage - main vs releases](#intended-usage---main-vs-releases)
   * [Environment Aware Testing](#environment-aware-testing)
   * [Tailoring to Your Environment](#tailoring-to-your-environment)
* [Running the Profile](#running-the-profile)
   * [(connected) Running the Profile Directly](#connected-running-the-profile-directly)
   * [(disconnected) Running the profile from a local archive copy](#disconnected-running-the-profile-from-a-local-archive-copy)
   * [Different Run Options](#different-run-options)
* [Using Heimdall for Viewing Test Results and Exporting for Checklist and eMASS](#using-heimdall-for-viewing-test-results-and-exporting-for-checklist-and-emass)

## RedHat 9.x Enterprise Linux Security Technical Implementation Guide (RHEL9 STIG)

The DISA RME and DISA SD Office, along with their vendor partners, create and maintain a set of Security Technical Implementation Guides for applications, computer systems and networks connected to the Department of Defense (DoD). These guidelines are the primary security standards used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

The RHEL9 STIG (see public.cyber.mil/stigs/) offers a comprehensive compliance guide for the configuration and operation your RedHat Enterprise Linux 9.x system.

The requirements associated with the RHEL9 STIG are derived from the [Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide) and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST) [Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53) Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The RHEL9.x STIG profile checks were developed to provide technical implementation validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing to enhance their security posture and can be tailored easily for use in your organization.

### Source Guidance

- RedHat Enterprise Linux 9 Security Technical Implementation Guide v1r2

### Current Profile Statistics

The profile will be tested on every commit and every release against both `vanilla` and `hardened` ubi and ec2 images using a CI/CD pipeline. The `vanilla` images are unmodified base images sourced from Red Hat itself. The `hardened` images have had their settings configured for security according to STIG guidance. Testing both vanilla and hardened configurations of both containerized and virtual machine implementations of RHEL9 is necessary to ensure the profile works in multiple environments.

Further pipelines may be employed to test different hardening content sources (e.g., Ansible code sourced directly from DISA or Red Hat).

# Getting Started and Intended Usage

1. It is intended and recommended that InSpec and the profile be run from a **"runner"** host, either from source or a local archieve - [Running the Profile](#running-the-profile) - (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [ remotely over **ssh**].

2. **For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.**

3. The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

4. Always use the latest version of the `released profile` (see below) on your system.

## Intended Usage - `main` vs `releases`

1. The latest `released` version of the profile is intended for use in A&A testing, as well as providing formal results to Authorizing Officials and IAMs. Please use the `released` versions of the profile in these types of workflows.

2. The `main` branch is a development branch that will become the next release of the profile. The `main` branch is intended for use in _developing and testing_ merge requests for the next release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.

## Environment Aware Testing

The RHEL9.x STIG profile is `container aware` and is able to determine when the profile is being executed inside or outside a `docker container` and will only run the tests that are approporate for the enviroment it is testing in. The tests are all tagged as `host` or `host, container`.

All the profile's tests (`controls`) apply to the `host` but many of the controls are `Not Applicable` when running inside a `docker container` (such as, for example, controls that test the system's GUI). When running inside a `docker container`, the tests that only applicable to the host will be marked as `Not Applicable` automatically.

## Tailoring to Your Environment

### Profile Inputs (see `inspec.yml` file)

This profile uses InSpec Inputs to make the tests more flexible. You are able to provide inputs at runtime either via the cli or via YAML files to help the profile work best in your deployment.

#### **_Do not change the inputs in the `inspec.yml` file_**

The `inputs` configured in the `inspec.yml` file are **profile definition and defaults for the profile** and not for the user. InSpec provides two ways to adjust the profiles inputs at run-time that do not require modifiying `inspec.yml` itself. This is because automated profiles like this one are frequently run from a script, inside a pipeline or some kind of task scheduler. Such automation usually works by running the profile directly from its source (i.e. this repository), which means the runner will not have access to the `inspec.yml`.

To tailor the tested values for your deployment or organizationally defined values, **_you may update the inputs_**.

#### Update Profile Inputs from the CLI or Local File

1. Via the cli with the `--input` flag
2. Pass them in a YAML file with the `--input-file` flag.

More information about InSpec inputs can be found in the [InSpec Inputs Documentation](https://docs.chef.io/inspec/inputs/).

#### See the `inspec.yml` file for full list of available inputs

Example Inputs

```yaml
  TODO
```

# Running the Profile

## (connected) Running the Profile Directly

```
inspec exec https://github.com/mitre/redhat-enterprise-linux-9-stig-baseline/archive/main.tar.gz --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>
```

## (disconnected) Running the profile from a local archive copy

If your runner is not always expected to have direct access to the profile's hosted location, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/redhat-enterprise-linux-9-stig-baseline.git
inspec archive redhat-enterprise-linux-9-stig-baseline
<sneakerNet your archive>
inspec exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

1. Delete and recreate your archive as shown above
2. Update your archive with the following steps

```
cd redhat-enterprise-linux-9-stig-baseline
git pull
cd ..
inspec archive redhat-enterprise-linux-9-stig-baseline
```

## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

# Using Heimdall for Viewing Test Results and Exporting for Checklist and eMASS

The JSON results output file can be loaded into **[Heimdall](https://heimdall-lite.mitre.org/)** for a user-interactive, graphical view of the profile scan results. Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.

It can also **_export your results into a DISA Checklist (CKL) file_** for easily upload into eMass using the `Heimdall Export` function.

Depending on your enviroment, you can also use the [SAF CLI](https://saf-cli.mitre.org) to run a local docker instance of heimdall-lite via the `saf view:heimdall` command.

The JSON results file may also be loaded into a **[full Heimdall Server](https://github.com/mitre/heimdall2)**, allowing for additional functionality such as to store and compare multiple profile runs.

You can deploy your own instances of Heimdall-Lite or Heimdall Server easily via docker, kurbernetes, or the installation packages.

# Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

MITRE Security Automation Framework Team https://saf.mitre.org

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
