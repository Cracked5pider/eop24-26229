# Firebeam CVE-2024-26229 plugin

A small firebeam (kaine's risc-v vm) plugin to exploit the CVE-2024-26229 vulnerability that utilizes a vulnerable IOCTL in csc.sys. 
The vulnerability is used to get kernel R/W memory access to corrupt the KTHREAD->PreviousMode and then to leveraging DKOM to achieve LPE by copying over the token from the system process over to the current process token.

![preview](https://raw.githubusercontent.com/Cracked5pider/eop24-26229/main/assets/image.png)

### credits
- [original CVE-2024-26229 repo](https://github.com/varwara/CVE-2024-26229)
- Eric Egsgard Talk at [OffensiveCon24 (video)](https://www.youtube.com/watch?v=2eHsnZ4BeDI)
