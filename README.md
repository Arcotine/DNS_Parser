# Examples of DNS Messages

Below are some examples DNS messages with their expected outputs. Several different hex formatted strings are supported, including multiple lines, hex word separation with specific characters ('x', '\'), and quotation marks. 

## One
    "\xa0\x1d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61" \
    "\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00" \
    "\x01\x00\x01\x00\x00\x1b\xbc\x00\x04\x5d\xb8\xd8\x22"


## Two
    \x9b\x4c\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00\x03\x77\x77\x77\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x10\x7c\x60\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x10\x7b\x60


## Three
    x7exbdx84x00x00x01x00x02x00x00x00x00x03x77x77x77x0ax63x6cx6fx75x64x66x6cx61x72x65x03x63x6fx6dx00x00x1cx00x01xc0x0cx00x1cx00x01x00x00x01x2cx00x10x26x06x47x00x00x00x00x00x00x00x00x00x68x10x7cx60xc0x0cx00x1cx00x01x00x00x01x2cx00x10x26x06x47x00x00x00x00x00x00x00x00x00x68x10x7bx60


## Four
    "\x76\x20\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x77\x77\x77" \
    "\x07\x73\x70\x6f\x74\x69\x66\x79\x03\x63\x6f\x6d\x00\x00\x01\x00" \
    "\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x01\x02\x00\x1f\x12\x65\x64" \
    "\x67\x65\x2d\x77\x65\x62\x2d\x73\x70\x6c\x69\x74\x2d\x67\x65\x6f" \
    "\x09\x64\x75\x61\x6c\x2d\x67\x73\x6c\x62\xc0\x10\xc0\x2d\x00\x01" \
    "\x00\x01\x00\x00\x00\x6c\x00\x04\x23\xba\xe0\x19"


## Five
    "\x61\x93\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61" \
    "\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01\xc0\x0c\x00" \
    "\x1c\x00\x01\x00\x00\x1b\xf9\x00\x10\x26\x06\x28\x00\x02\x20\x00" \
    "\x01\x02\x48\x18\x93\x25\xc8\x19\x46"
