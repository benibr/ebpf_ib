# ebpf\_ib - eBPF interface bonder

This is a proof-of-concept of how one can implement a IP packets egress distribution over two network interfaces
with eBPF.
A usecase is a router which should emit packets on two interfaces but no bonding or teaming can be used.
Eg. with the IPoIB driver.


## Credits

This repo was originally derived from [github.com/ldelossa/ebpf-net](https://github.com/ldelossa/ebpf-net). Thanks for the input!
