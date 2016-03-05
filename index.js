var fs = require('fs');
var crypto = require('crypto');
var process = require('process');
var path = require('path');

/**
 * Checks if a path exists
 *
 * @param  {String} path - path to check
 * @return {Boolean} - true if path exists, false if otherwise
 */
function pathExists(path) {
  try {
    fs.accessSync(path, fs.F_OK);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * getUserHome - http://stackoverflow.com/questions/9080085/node-js-find-home-directory-in-platform-agnostic-way
 *
 * @return {String}  returns the user's home directory
 */
function getUserHome() {
  return process.env[(process.platform == 'win32') ? 'USERPROFILE' : 'HOME'];
}

function verify() {
  return (host, hash) => {
    return this.hostCheck(host) && this.hostKeyHash == hash;
  }
}


/**
 * Returns a function that is attached to 'hostCheck' on key object
 * The hostCheck function takes a host or IP and returns true or false
 * if the key matches or doesn't
 * This version is for hashed keys
 *
 * @param  {Buffer} key      used internally
 * @param  {String} hostHash used internally
 * @return {function}        hostCheck function
 */
function hostCheckHash(key, hostHash) {
  return (host) => {
    var hmac = crypto.createHmac('sha1', key);
    hmac.update(host);
    return hmac.digest().toString('base64') === hostHash;
  }
}

/**
 * Returns a function that is attached to 'hostCheck' on key object
 * The hostCheck function takes a host or IP and returns true or false
 * if the key matches or doesn't
 * This version is for normal (non-hashed) keys
 *
 * @param  {Buffer} key      used internally
 * @param  {String} hostHash used internally
 * @return {function}        hostCheck function
 */
function hostCheckNormal(ip, host) {
  return (checkHost) => {
    return (host === checkHost || ip === checkHost);
  }
}


/**
 * Takes either a filename, a string with known_hosts file contents or nothing
 * and returns a list of parsed keys
 *
 * @param  {multiple} fn
 * @return {Array}    Array with multiple objects representing keys
 */
function parseKnownHostsFile(fn) {
  if (typeof fn === "undefined") {
    fn = path.join(getUserHome(), '.ssh', 'known_hosts');
  }
  var keys = [];
  var lns = [];
  if (pathExists(fn)) {
    lns = String(fs.readFileSync(fn)).replace("\r\n", "\n").split("\n");
  } else {
    lns = String(fn).replace("\r\n", "\n").split("\n");
  }

  lns.forEach((ln) => {
    var rv = {ip: "", host: "", hostKeyHash:"", type: "", hostCheck: () => { return true }, encryptedHost: false};
    var els = ln.split(' ');
    if (els.length != 3) return;
    var hostIPsec = els[0];
    var typeSec = els[1];
    var hashSec = els[2];
    if (hostIPsec.indexOf('|1|') > -1) {
      // this section processes hashed keys or hostnames
      // when the ssh config option HashKnownHosts is set to 'yes'
      // note: always stores hashed host/ip as host

      rv.encryptedHost = true;
      var eh = hostIPsec.replace('|1|', '');
      var key = new Buffer(eh.split('|')[0], 'base64');
      var hh = eh.split('|')[1];
      rv.host = hh;
      rv.hostCheck = hostCheckHash(key, hh);
      rv.verify = verify();
    } else {
      // this section processes normal hostnames

      if (hostIPsec.indexOf(",") > -1 ) {
        var hip = hostIPsec.split(',');
        rv.host = hip[0];
        rv.ip = hip[1];
      } else {
        // Quick and cheap IP matching, currently online ipv4.
        if (hostIPsec.match(/^[0-9.]+$/g)) {
          rv.ip = hostIPsec;
        } else {
          rv.host = hostIPsec;
        }
      }
      rv.hostCheck = hostCheckNormal(rv.ip, rv.host);
      rv.verify = verify();
    }

    // assign the key type
    rv.type = typeSec;

    // compute the sha1 of the base64 key

    var key = new Buffer(hashSec, 'base64');
    var hash = crypto.createHash('sha1');
    hash.update(key);
    rv.hostKeyHash = hash.digest('hex');
    keys.push(rv);
  });
  return keys;
}

function main() {
  var keys = parseKnownHostsFile();
  console.log(keys);
}


if (require.main === module) {
    main();
}


exports.parseKnownHostsFile = parseKnownHostsFile;
