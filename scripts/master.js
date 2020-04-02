require("dotenv").config();
const crypto = require('crypto')
const ursa = require('ursa')
const prompt = require('prompt')
const R = require("ramda");
const await = require("asyncawait/await");
const async = require("asyncawait/async");
const models = require("../models");
var fs = require('fs');
const child_process = require('child_process');
let existingKeys = [];

// Create table if not exists
models.Keys.sync();  
var schema = {
  properties: {
    password: {
      description: 'Enter master password',
      hidden: true,
      replace: '*',
      required: true,
      type: 'string',
    },
    repassword: {
      description: 'Re-Enter master password',
      hidden: true,
      replace: '*',
      required: true,
      type: 'string',
      conform: function (repassword) {
        var password = prompt.history('password').value;
        return (password == repassword);
      }
    },
    numKeys: {
      description: 'Number of keys to generate',
      required: true,
      type: 'number'
    },
    numReservedKeys: {
      description: 'Number of reserved keys to set',
      required: true,
      type: 'number'
    }
  }
}


function bulkCreateKeysUser() {
  prompt.start()
  prompt.get(schema, function (err, result) {
    if (err) {
      return console.log(err);
    }
    password = result.password;
    var keys = getKeys(password, result.numKeys, result.numReservedKeys, false)
    if (writeToFile("./keys/keys.json", keys)) {
      console.log("Keys created...")
    }
    models.Keys.bulkCreate(keys)
      .then(sc => {
        console.log("Keys successfully written to DB");
        delete schema.properties.numKeys;
        prompt.get(schema, function (err, result) {
          if (err) {
            return console.log(err);
          }
          password = result.password;
          if (verifyEncryption(keys, password)) {
            console.log("Verification successful...")
          }
        });
      })
      .catch(err => {
        console.log("Error adding keys to db", err);
      })
  });
}

function bulkAppendKeys(master) {
  password = process.env.ENTRY_PASS;
  if (password === '' || !password) {
    console.log("No password provided. Quitting...");
  }
  var keys = getKeys(password, process.env.N_KEYS, process.env.N_RESERVED_KEYS, true, master);

  models.Keys.bulkCreate(keys).then(sc => {
      console.log("Keys successfully written to DB");
      delete schema.properties.numKeys;
      // Add the new keys to existing keys
      keys.concat(existingKeys);

      if (verifyEncryption(keys, password, master)) {
        console.log("Verification successful...")
      } else {
        console.log("Bulk append - Error verification of keys")
      }
    })
  .catch(err => {
    console.log("Error adding keys to db", err);
  })
}

function bulkCreateKeys() {
  password = process.env.ENTRY_PASS;
  if (password === '' || !password) {
    console.log("No password provided. Quitting...");
  }
  var keys = getKeys(password, process.env.N_KEYS, process.env.N_RESERVED_KEYS, false);
  models.Keys.bulkCreate(keys).then(sc => {
    console.log("Keys successfully written to DB");
    delete schema.properties.numKeys;
    if (verifyEncryption(keys, password)) {
      console.log("Verification successful...")
    } else {
      console.log("Bulk create - Error verification of keys")
    }
    })
  .catch(err => {
    console.log("Error adding keys to db", err);
  })
}


const writeToFile = (fileName, keys) => {
  fs.writeFile(fileName, JSON.stringify(keys), function (err) {
    if (err) {
      return console.log(err);
    }
  });
  return true;
}

const createZip = (inputFile) => {
  var createKeyZip = child_process.spawn('zip', ['--encrypt', './keys/keys.zip', inputFile]);
  createKeyZip.stdout.on('data', function (data) {
    // console.log('stdout: ' + data);
  });
  createKeyZip.stderr.on('data', function (data) {
    if (data.includes('Enter')) {
      console.log("Enter password for zip: ")
    } else if (data.includes('Verify')) {
      console.log("Verify password for zip: ")
    }
  });

  createKeyZip.on('close', function (code) {
    var destroyKeyjson = child_process.spawn('rm', ['-rf', 'decryptedKeys.json']);
    console.log("keys.json and keys.zip has been saved in ./keys directory")
    console.log("REMEMBER MASTER AND ZIP PASSWORD")
    console.log('Warning: Nothing will work without master password');
  });
}

const verifyEncryption = (keys, password, master) => {
  var result = false;
  let decryptedKeys = []
  let masterKey = ""
  if (master) {
    masterKey = master
  } else {
    masterKey = getMasterKey(keys)
  }
  if (masterKey != null) {    
    decryptedKeys.push(masterKey)
    for (var i = 0; i < keys.length; i++) {
      if (keys[i]["type"] == "OTHER") {
        let key = {}
        key.public = keys[i]["public"]
        key.private = rsaDecryptChunks(keys[i]["private"], masterKey.private)
        key.type = keys[i]["type"]
        key.active = keys[i]["active"]
        key.reserved = keys[i]["reserved"]
        decryptedKeys.push(key)
      }
    }
    if (process.argv.length == 2 && writeToFile("decryptedKeys.json", decryptedKeys)) {
      createZip("decryptedKeys.json")
    }
    result = true
  } else {
    console.log("master key is null")
  }
  return result
}

const getMasterKey = (keys) => {
  for (var i = 0; i < keys.length; i++) {
    if (keys[i]["type"] == "MASTER") {
      let key = {}
      key.public = keys[i]["public"]
      key.private = decMasterKey(keys[i]["private"], password)
      key.type = "MASTER"
      key.active = true
      if (key.private == null) { return null }
      console.log("Found at least one master")
      return key
    }
  }
}

const convertPemToString = (pemKey) => {
  var pemKeyArray = pemKey.split('\n')
  var stringPemKey = "";
  for (var i = 1; i < pemKeyArray.length - 2; i++) {
    stringPemKey += pemKeyArray[i]
  }

  // console.log("newlines count in this key = " + pemKeyArray.length)
  // console.log("stringPemKey length = " + stringPemKey.length)

  return stringPemKey
}

/**
 * Chunking the large private key to chunks of 424.
 * 424 is a number that we recognized was working fine and the same
 * is being used here.
 * @param {string} pemKey 
 */
const chunkifyPemString = (pemKey) => {
  var pemKeyString = convertPemToString(pemKey)

  var pemKeyArray = pemKeyString.match(/.{1,424}/g);
  return pemKeyArray
}

// Dechunk
const rsaDecryptChunks = (chunkedStr, key) => {
  var arrChunks = chunkedStr.split("|")
  
  let result = ""
  for (idx = 0; idx < arrChunks.length; idx++) {
    result += rsaDecryption(arrChunks[idx], key)
  }

  return result
}

const getKeys = (password, numKeys, numReservedKeys, isAppendMode, masterKey) => {
  let keys = [];
  let master = masterKey
  if (!isAppendMode) {
    // Not append mode. Generate a new master password
    console.log("is not append mode")
    master = generateKey(password);
    keys.push(master)
  } else {
    console.log("Running in append mode. Keys required = " + numKeys + ": Reserved = " + numReservedKeys)
  }

  //console.log("master is here " + JSON.stringify(master));

  let reservedCount = 0;
  for (var i = 0; i < numKeys; i++) {
    console.log("Creating key " + i)
    var keypair = ursa.generatePrivateKey(2048);
    let key = {};
    key.public = convertPemToString(keypair.toPublicPem().toString());
    let privatePem = keypair.toPrivatePem().toString();
    let chunks = chunkifyPemString(privatePem);
    let encChunks = ""

    for (idx = 0; idx < chunks.length; idx++) {
      encChunks += rsaEncryption(chunks[idx], master.public) + "|"
    }
    // trim off the last pipe symbol
    key.private = encChunks.slice(0, -1);

    // | when base64 will result in fA==
    // When | or its base64 equivalent is put into encryption, it will always result in a
    // long string and therefore it is okay to use pipe | as a separator for the chunks.
    // console.log(rsaEncryption("fA==", master.public))
    // console.log(rsaEncryption("|", master.public))

    key.type = "OTHER";
    key.active = true;
    key.reserved = (reservedCount < numReservedKeys);
    reservedCount++

    keys.push(key);
  }
  return keys;
};

const generateKey = (password) => {
  var keys = { "key": {} }
  var keypair = ursa.generatePrivateKey(4096);
  keys.key.public = convertPemToString(keypair.toPublicPem().toString())
  keys.key.private = encMasterKey(convertPemToString(keypair.toPrivatePem().toString()), password)
  keys.key.type = "MASTER";
  keys.key.active = true;
  return keys.key;
};

const encMasterKey = (key, password) => {
  var cipher = crypto.createCipher("aes-128-cbc", password)
  var crypted = cipher.update(key, 'utf8', 'hex')
  crypted += cipher.final('hex');
  return crypted;
};

const rsaEncryption = (message, publicKey) => {
  var crt = ursa.createPublicKey('-----BEGIN PUBLIC KEY-----\n' + publicKey + '\n' + '-----END PUBLIC KEY-----')
  return crt.encrypt(message, 'utf8', 'base64', ursa.RSA_PKCS1_PADDING)
}

const rsaDecryption = (message, privateKey) => {
  var crt = ursa.createPrivateKey('-----BEGIN RSA PRIVATE KEY-----\n' + privateKey + '\n' + '-----END RSA PRIVATE KEY-----')
  return crt.decrypt(message, 'base64', 'utf8', ursa.RSA_PKCS1_PADDING);
};

const decMasterKey = (key, password) => {
  try {
    var decipher = crypto.createDecipher("aes-128-cbc", password)
    var decrypted = decipher.update(key, 'hex', 'utf8')
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.log("Could not decrypt master key, Verification unsuccessful")
    return null;
  }
}

loadKeysFromDB = async(() => {  
  return models.Keys.findAll({});
})

loadMasterKey = async( () => {
  let password = await(getDbPassword());
  existingKeys = await(loadKeysFromDB());
  existingKeys = R.map(key=>key.dataValues,existingKeys);
  console.log("keys count = " + existingKeys.length)
  return getMasterKey(existingKeys);
})

getMasterPassword = (resolve,reject) => {
  password = process.env.ENTRY_PASS;
  resolve(password);
};

getDbPassword = () => {
  return new Promise((resolve, reject) => {
    getMasterPassword(resolve, reject);
  });
};


if (process.argv.length == 2) {
  console.log("Running in dev mode.")
  bulkCreateKeysUser()
} else {
  loadMasterKey().then((data) => {
    if (data === undefined) {
      console.log("No master key found");
      console.log("Running in silent CREATE mode. Looking for master env vars..")
      bulkCreateKeys()
    } else {
      if (process.env.APPEND === "true") {
        console.log("Running in silent APPEND mode. Looking for master env vars..")
        bulkAppendKeys(data)
      } else {
        console.log("No changes done to keys in db")
      }
    }
  })
}
