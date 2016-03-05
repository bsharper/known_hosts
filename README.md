# known_users
This is a really simple package to read and parse known_users files. This can be useful when you want to verify that the SSH host you are talking to is legitimate.

## Usage
```js
var known_hosts = require('known_hosts');
var Client = require('ssh2').Client; // https://github.com/mscdex/ssh2

var keys = known_hosts.parseKnownHostsFile();
...
var connectionOptions = {
	    hostHash: 'sha1',
		    hostVerifier: function (serverKeyHash) {
				        var valid = false;
						        keys.forEach(function (k) {
									            if (k.verify(remoteHost, serverKeyHash)) valid = true;
												        });
								        return valid;
										    }
}

```
Running the parseKnownHostsFile without any arguments will try to use the known hosts file under your user directory (~/.ssh/known_hosts). You can also pass it a file path to another file, or a string to be parsed.

## Key Types

This module handles both encrypted and unencrypted keys. If the 'HashKnownHosts' option in either /etc/ssh/ssh_config or ~/.ssh/config is set to 'Yes', your hosts file will be encrypted. The salt is stored in the known_hosts file, so we can verify against it. Until the correct IP or hostname is provided, there's no way to know what that host points to. This is generally a good idea, since it makes attacking hosts in your known_hosts file harder if an attacker gets control of your computer.

## Questions, comments, concerns?
Let me know if there's an issue or something you'd like added. I wrote this as a quick and easy way to check hosts while using the ssh2 npm module. That module provides sha1 key hashes to hostVerifier which is why the hostKey hash is generated as sha1. I wrote known_hosts this morning, so there may be bugs.
