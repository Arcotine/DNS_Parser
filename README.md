# **DNS Parser**
A command line program that converts hex encoded DNS messages into a human readable text format.

## Building
To build, navigate to the root directory and enter the command:

`CMake ${DIRECTORY_FOR_BUILD}`

Alternatively, you can use an editor with CMake plugin support (such as VSCode) to build and run. Or compile it manually with your favorite compiler, such as g++

## Running
Start the newly built executable in the directory you chose via the command line. Enter your hex data in one of the supported formats (see [DNS Message Examples](#DNS-Message-Examples)).

**Important: to finish entering hex data, type**

 `exit` 

in its own line. The program will interpret everything before this as part of the DNS Message.

# DNS Message Examples

Below are some examples DNS messages with their expected outputs. Several different hex formatted strings are supported, including multiple lines, hex word separation with specific characters ('x', '\'), and quotation marks. 

## Example Format #1
### Hex String
```
"\xa0\x1d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61" \
"\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00" \
"\x01\x00\x01\x00\x00\x1b\xbc\x00\x04\x5d\xb8\xd8\x22"
```
### Expected Output
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40989
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.           IN      A

;; ANSWER SECTION:
example.com.            7100    IN      A       93.184.216.34
```

## Example Format #2
### Hex String
```
\x9b\x4c\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00\x03\x77\x77\x77\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x10\x7c\x60\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x10\x7b\x60
```
### Expected Output
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39756
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.cloudflare.com.            IN      A

;; ANSWER SECTION:
www.cloudflare.com.             300     IN      A       104.16.124.96
www.cloudflare.com.             300     IN      A       104.16.123.96
```

## Example Format #3
### Hex String
```
x7exbdx84x00x00x01x00x02x00x00x00x00x03x77x77x77x0ax63x6cx6fx75x64x66x6cx61x72x65x03x63x6fx6dx00x00x1cx00x01xc0x0cx00x1cx00x01x00x00x01x2cx00x10x26x06x47x00x00x00x00x00x00x00x00x00x68x10x7cx60xc0x0cx00x1cx00x01x00x00x01x2cx00x10x26x06x47x00x00x00x00x00x00x00x00x00x68x10x7bx60
```
### Expected Output
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32445
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.cloudflare.com.            IN      AAAA

;; ANSWER SECTION:
www.cloudflare.com.             300     IN      AAAA    2606:4700::6810:7c60
www.cloudflare.com.             300     IN      AAAA    2606:4700::6810:7b60
```

## Example Format #4
### Hex String
```
762081800001000200000000037777770773706f7469667903636f6d0000010001c00c0005000100000102001f12656467652d7765622d73706c69742d67656f096475616c2d67736c62c010c02d000100010000006c000423bae019
```
### Expected Output
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30240
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.spotify.com.               IN      A

;; ANSWER SECTION:
www.spotify.com.                258     IN      CNAME   edge-web-split-geo.dual-gslb.spotify.com.
edge-web-split-geo.dual-gslb.spotify.com.               108     IN      A       35.186.224.25
```


## Example Format #5
### Hex String
```
"\x61\x93\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61"
"\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01\xc0\x0c\x00"
"\x1c\x00\x01\x00\x00\x1b\xf9\x00\x10\x26\x06\x28\x00\x02\x20\x00"
"\x01\x02\x48\x18\x93\x25\xc8\x19\x46"
```
### Expected Output
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24979
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.           IN      AAAA

;; ANSWER SECTION:
example.com.            7161    IN      AAAA    2606:2800:220:1:248:1893:25c8:1946
```
