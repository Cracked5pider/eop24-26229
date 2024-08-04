# Firebeam CVE-2024-26229 plugin

A small firebeam (kaine's risc-v vm) to exploit the CVE-2024-26229 vulnerability that utilizes a vulnerable IOCTL in csc.sys for kernel memory R/W access to corrupt the KTHREAD->PreviousMode and then to leveraging DKOM to achieve LPE by copying over the token from the system process over to the current process token.

![preview](https://raw.githubusercontent.com/Cracked5pider/eop24-26229/main/assets/image.png)

### credits
- [original CVE-2024-26229 repo](https://github.com/varwara/CVE-2024-26229)
- Eric Egsgard Talk at [OffensiveCon24 (video)](https://www.youtube.com/watch?v=2eHsnZ4BeDI)
