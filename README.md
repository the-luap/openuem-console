# OpenUEM - Console

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Console is OpenUEM's Web User Interface

This fork adds native iOS/iPadOS enrollment, inventory, configuration profiles
and declarative OS update policies alongside the existing Windows management.
See the [Apple management operator guide](docs/native-ios-operations.md) for
setup, supported workflows, verification and current limitations. The device
protocol implementation is part of this console; NanoMDM is not a dependency.

![OpenUEM console](https://github.com/user-attachments/assets/795cf36c-91ed-40e2-8b3a-abcff5d46305)

The console allows you to perform the following actions:

- Admit, enable or disable an agent that contacts OpenUEM Agent Workers
- Browse an endpoint's information gathered by an agent
- Start a VNC remote assistance session
- Browse the files contained in an endpoint's logical disks
- Deploy a package to an endpoint using Winget. You can also uninstalled packages deployed by OpenUEM
- Create profiles to automate tasks to deploy software and manage settings (registry, local user, local groups...)
- Wake On Lan, power off and reboot endpoints
- Get statistics and check the status of the different OpenUEM components

Now more about the console in [OpenUEM documentation](https://openuem.eu/docs/Console/intro)
