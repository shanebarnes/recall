# recall
Profile memory on Unix systems using the LD_PRELOAD trick

## Examples

### macOS

```
$ cmake -H. -Bbuild
$ cd build/
$ make
$ export RECALL_BT_DISPLAY_INTERVAL=1; DYLD_INSERT_LIBRARIES=$PWD/librecall.0.0.1.dylib ./leak
Recall init: started
Recall init: loaded calloc, 0x7fff2027f5bd
Recall init: loaded malloc, 0x7fff2027d510
Recall init: loaded realloc, 0x7fff2027f45d
Recall init: loaded free, 0x7fff2027e0bc
Recall init: loaded CRYPTO_free, 0x0
Recall init: loaded CRYPTO_malloc, 0x0
Recall init: loaded CRYPTO_realloc, 0x0
Recall init: loaded CRYPTO_zalloc, 0x0
Recall init: finished
RECALL_BT_CAPTURE_MINSIZE = 8192
RECALL_BT_DISPLAY_INTERVAL = 1

Memory Size Distribution:
   size         frequency
<= 131072       1

Total unique threads: 1

function               total          use       max       min       avg     calls
c.calloc                   0            0         0         0         0         0
c.malloc                   0            0         0         0         0         0
c.realloc                  0            0         0         0         0         0
c.free                     0            0         0         0         0         0
cpp.new               196608       131072    131072     65536    196608         2
cpp.delete             65536            0     65536     65536     65536         1
crypto.malloc              0            0         0         0         0         0
crypto.realloc             0            0         0         0         0         0
crypto.zalloc              0            0         0         0         0         0
crypto.free                0            0         0         0         0         0
internal.new               5            3         0         0         0         5
internal.delete            2            0         0         0         0         2
net total             131075       131075         0         0         0         4
Recall fini: done
```