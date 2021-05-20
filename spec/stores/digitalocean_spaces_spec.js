/* eslint-env mocha, chai, node */
const DigitalOceanSpaces = require('../../lib/stores/digitalocean_spaces');
const { itBehavesLike } = require('bdd-lazy-var');
require('../store_spec');

describe('DigitalOceanSpaces store', () => {
  let store = new DigitalOceanSpaces({
    bucket: process.env.BUCKET,
    endpoint: process.env.ENDPOINT,
    accessKeyId: process.env.ACCESS_KEY_ID,
    secretAccessKey: process.env.SECRET_ACCESS_KEY
  });

  after(async () => {
    await store._purgeAllContent();
  });
  itBehavesLike('Stores', store);
});
