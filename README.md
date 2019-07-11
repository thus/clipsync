Clipsync
========

Synchronize clipboards on multiple computers using files on a remote
file system.

The clipboards are encrypted before written to files to enable use on
remote file systems shared by multiple users. This ensures that the
content of the clipboards, which may be passwords or other sensitive
data, is kept secret. It also ensures that no other users tampers with
the content of the clipboards.

```
USAGE: clipsync
Synchronize clipboards.

OPTIONS:
	-d <dir>   : synchronize using this directory
	-l <file>  : log output to this file
	-L <level> : log level (debug/info/notice/warning/error)
	-p <pw>    : password used to encrypt clipboard data
	-h         : print this help
```

It is also possible to use the environment variable 'SYNC_PASSWORD' to
provide the encryption password to clipsync.

Installation
------------

Clipsync depends on libsodium for encryption/decryption:

```bash
$ apt install libsodium-dev
```

Cmake is used, so compile and install like this:

```bash
$ mkdir build
$ cmake ..
$ make
$ make install
```

Remote File Systems
-------------------

For clipsync to work, the remote file system must support atomic rename
(man 2 rename). The reason for this is that rename is used to share the
sync file between different instances of clipsync without locking.

The following remote file systems has been tested so far:

* NFS (works)
* CIFS version 3.0 (works) - could not get version 2.1 to work
* SSHFS (doesn't work) - not even with workaround=rename
