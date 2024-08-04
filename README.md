# Firebeam CVE-2024-26229 plugin

A small firebeam (kaine's risc-v vm) to exploit the CVE-2024-26229 vulnerability that utilizes a vulnerable IOCTL in csc.sys for kernel memory R/W access to corrupt the KTHREAD->PreviousMode and then to leveraging DKOM to achieve LPE by copying over the token from the system process over to the current process token.

![preview](https://github.com/Cracked5pider/eop24-26229/main/assets/image.png)

### credits
- https://nvd.nist.gov/vuln/detail/CVE-2024-26229
- https://github.com/varwara/CVE-2024-26229