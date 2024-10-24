const forge = require('node-forge');

module.exports.templateTags = [
  {
    "name": "shaWithRSA",
    "displayName": "SHAwithRSA",
    "description": "Generate digital signature using SHA and RSA",
    "args": [
      {
        "displayName": "Algorithm SHA",
        "type": "enum",
        "defaultValue": "sha512",
        "options": [
          { "displayName": "SHA1", "value": "sha1" },
          { "displayName": "SHA224", "value": "sha224" },
          { "displayName": "SHA256", "value": "sha256" },
          { "displayName": "SHA384", "value": "sha384" },
          { "displayName": "SHA512", "value": "sha512" },
        ]
      },
      {
        "displayName": "Private Key",
        "description": "Private key in PEM Format base64 encoded",
        "type": "string",
        "placeholder": "Enter your private key in PEM Format base64 encoded"
      },
      {
        "displayName": "Data (Digest)",
        "description": "Data to be signed (Digest)",
        "type": "string",
        "placeholder": "Enter your data (Digest)"
      }
    ],
    async run (context, algorithm, privateKeyEncoded, dataDigest) {
      console.log('device', context.request);
      const privateKeyDecoded = forge.util.decode64(privateKeyEncoded);
      const privateKey = forge.pki.privateKeyFromPem(privateKeyDecoded);
      let hash;
      switch (algorithm) {
        case "sha1": hash = forge.md.sha1.create(); break;
        case "sha224": hash = forge.md.sha224.create(); break;
        case "sha256": hash = forge.md.sha256.create(); break;
        case "sha384": hash = forge.md.sha384.create(); break;
        case "sha512": hash = forge.md.sha512.create(); break;
      }
      hash.update(dataDigest, 'utf8');
      const signature = privateKey.sign(hash);
      return String(forge.util.encode64(signature));
    }
  }
];

module.exports.requestHooks = [
  async (context) => {
    const req = context.request;

    const deviceId = req.getEnvironmentVariable('device_id');
    console.log('deviceId', deviceId);
    if (deviceId === undefined || deviceId === '') {
      throw new Error('Device ID is required');
    }

    req.setHeader("x-device-id", deviceId);
  },
];
    
