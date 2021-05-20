const core = require('./core');
const S3 = require('@aws-sdk/client-s3');
const path = require('path');

class DigitalOceanSpaces {
  /**
   * options: {
   *  bucket: string, // will be created if it doesn't exist
   *  endpoint: string,
   *  accessKeyId: string,
   *  secretAccessKey: string
   * }
   */
  constructor (options) {
    this._dir = options.bucket;
    this._bucket_created = false;

    this._s3 = new S3.S3Client({
      endpoint: options.endpoint,
      region: 'us-east-1',
      credentials: {
        accessKeyId: options.accessKeyId,
        secretAccessKey: options.secretAccessKey
      }
    });
  }

  async _purgeAllContent () {
    try {
      const res = await this.listObjects();
      const keys = res.Contents.map(c => c.Key);
      await this.deleteObjects(keys);
    } catch (e) {
      console.trace(e);
    }
  }

  _destroyBucket () {
    return this._s3.send(new S3.DeleteBucketCommand({
      Bucket: this._dir
    }));
  }

  _resolvePath (username, pathname) {
    return path.join(username.substr(0, 2), username, pathname);
  }

  _authPath (username) {
    return this._resolvePath(username, 'auth.json');
  }

  _metaPath (username, pathname, isdir = false) {
    let p = this.dataPath(username, pathname);
    p = !isdir ? path.dirname(p) : p;
    return path.join(p, '.~meta');
  }

  _lock (username) {
    const lockPath = path.join(username.substr(0, 2), username, '.lock');
    return this._s3.send(new S3.PutObjectLegalHoldCommand({
      Bucket: this._dir,
      Key: lockPath,
      LegalHold: 'ON'
    }));
  }

  _unlock (username) {
    const lockPath = path.join(username.substr(0, 2), username, '.lock');
    return this._s3.send(new S3.PutObjectLegalHoldCommand({
      Bucket: this._dir,
      Key: lockPath,
      LegalHold: 'OFF'
    }));
  }

  _versionMatch (versions, modified) {
    if (!versions || !modified) return false;
    return versions.find(version => modified === version.trim().replace(/"/g, ''));
  }

  async readMeta (username, pathname, isdir) {
    let metaData = await this.readJson(this._metaPath(username, pathname, isdir));
    if (!metaData) metaData = { items: {} };
    return metaData;
  }

  dataPath (username, pathname) {
    return this._resolvePath(username, 'storage/' + pathname);
  }

  async deleteObjects (keys) {
    return Promise.all(keys.map(key => this.deleteObject(key)));
  }

  async deleteObject (key) {
    const cmd = new S3.DeleteObjectCommand({
      Bucket: this._dir,
      Key: key
    });

    return this._s3.send(cmd);
  }

  async listObjects (path) {
    path = path || '';
    const cmd = new S3.ListObjectsCommand({
      Bucket: this._dir,
      Prefix: path
    });
    return this._s3.send(cmd);
  }

  async readFile (path, head = false) {
    return new Promise(async (resolve, reject) => {
      let data = [];
      const cmd = new S3.GetObjectCommand({
        Bucket: this._dir,
        Key: path
      });

      try {
        const res = await this._s3.send(cmd);
        if (head) {
          return resolve(res);
        }

        res.Body.on('data', (chunk) => {
          data.push(Buffer.from(chunk));
        });
        res.Body.on('end', () => {
          resolve(Buffer.concat(data));
        });
      } catch (e) {
        if (e.message === 'NoSuchKey') {
          resolve(null);
        }
      }
    });
  }

  async readJson (path) {
    const data = await this.readFile(path);
    try {
      return JSON.parse(data);
    } catch (e) {
      return data;
    }
  }

  readAuth (username) {
    return this.readJson(this._authPath(username));
  }

  async writeFile (path, data, type = 'application/octet') {
    await this.createBucketIfNotExists();
    const length = data instanceof Buffer ? data.byteLength : Buffer.from(data).byteLength;
    const cmd = new S3.PutObjectCommand({
      Bucket: this._dir,
      Key: path,
      Body: data,
      ContentLength: length,
      ContentType: type
    });
    return this._s3.send(cmd);
  }

  async createBucketIfNotExists () {
    try {
      if (!this._bucket_created) {
        await this._s3.send(new S3.CreateBucketCommand({
          Bucket: this._dir
        }));
        this._bucket_created = true;
      }
      return null;
    } catch (e) {
      if (e.message === 'BucketAlreadyExists') {
        this._bucket_created = true;
      } else {
        console.trace('Problem creating bucket', e.message);
      }
      return null;
    }
  }

  async createUser (params) {
    const errors = core.validateUser(params);
    if (errors.length > 0) throw new Error(errors[0]);

    const username = params.username;
    const authPath = this._authPath(username);
    const user = await this.readAuth(username);

    if (user) throw new Error('The username is already taken');

    const hash = await core.hashPassword(params.password, null);
    const data = { email: params.email, password: hash };
    return this.writeFile(authPath, JSON.stringify(data, true, 2), 'application/json');
  }

  async authenticate (params) {
    const username = params.username || '';
    const user = await this.readAuth(username);
    if (!user) throw new Error('Username not found');
    const key = user.password.key;
    const hash = await core.hashPassword(params.password, user.password);
    if (hash.key === key) return true;

    throw new Error('Incorrect password');
  }

  async authorize (clientId, username, permissions) {
    const token = core.generateToken();
    let user = await this.readAuth(username);
    let category;

    user.sessions = user.sessions || {};
    let session = user.sessions[token] = { clientId, permissions: {} };

    // use lodash
    for (let scope in permissions) {
      category = scope.replace(/^\/?/, '/').replace(/\/?$/, '/');
      session.permissions[category] = {};
      for (var i = 0, n = permissions[scope].length; i < n; i++) {
        session.permissions[category][permissions[scope][i]] = true;
      }
    }

    await this.writeFile(this._authPath(username),
      JSON.stringify(user, true, 2), 'application/json');

    return token;
  }

  async permissions (username, token) {
    const user = await this.readAuth(username);
    if (!user) return {};
    const data = user.sessions;
    if (!data || !data[token]) return {};

    const permissions = data[token].permissions;
    if (!permissions) return {};
    let output = {};

    for (const category in permissions) {
      output[category] = Object.keys(permissions[category]).sort();
    }

    return output;
  }

  async revokeAccess (username, token) {
    const user = await this.readAuth(username);

    if (user && user.sessions && user.sessions[token]) {
      delete user.sessions[token];
    }
    await this.writeFile(this._authPath(username), JSON.stringify(user, true, 2));
  }

  async get (username, pathname, versions, head = false) {
    versions = versions && versions.split(',');
    const isdir = /\/$/.test(pathname);
    const basename = decodeURI(path.basename(pathname)) + (isdir ? '/' : '');
    const datapath = this.dataPath(username, pathname);

    const metadata = await this.readMeta(username, pathname, isdir);

    // resource exists?
    let ret;
    if (!isdir && !metadata.ETag) ret = { item: null };
    if (!isdir && !metadata.items[basename]) ret = { item: null };
    if (ret) {
      return ret;
    }

    // has client the same version of this resource?
    const currentETag = isdir ? metadata.ETag : metadata.items[basename].ETag;
    if (this._versionMatch(versions, currentETag)) {
      return { item: metadata, versionMatch: true };
    }

    // dir listing
    if (isdir) {
      return { item: metadata };
    } else {
      // do not include content on head request
      const blob = await this.readFile(datapath, head);

      if (blob === null) return { item: null };
      const item = metadata.items[basename];
      item.value = blob;
      return { item, versionMatch: false };
    }
  }

  async put (username, pathname, type, value, version) {
    const datapath = this.dataPath(username, pathname);
    const metapath = this._metaPath(username, pathname);
    const basename = decodeURI(path.basename(pathname));
    const metadata = await this.readMeta(username, pathname);
    let created = false;

    if (version) {
      if (version === '*'
        // check document existence when version '*' specified
        ? metadata.items && metadata.items[basename]
        // check version matches when specified
        : !metadata.items || !metadata.items[basename] ||
          version.replace(/"/g, '') !== metadata.items[basename].ETag
      ) {
        return { conflict: true, created };
      }
    }

    if (metadata.items[`${basename}/`]) {
      return { isDir: true, created };
    }

    // check if something in this path is already a file
    const paths = core.traversePath(pathname);
    const dirConflicts = (await Promise.all(
      paths.map(async ({ currentPath }) => {
        return this.readMeta(username, currentPath, true);
      }))).some((meta, i) => {
      const upperBasename = paths[i].upperBasename;
      return (upperBasename !== basename && meta.items && meta.items[upperBasename]);
    });

    if (dirConflicts) {
      return { created, isDir: true };
    }

    try {
      await this.writeFile(datapath, value, type);
      const modified = Date.now().toString();
      created = !metadata.items.hasOwnProperty(basename);
      // update metadata
      metadata.items[basename] = {
        ETag: modified,
        'Content-Type': type,
        'Content-Length': value.length
      };
      metadata.ETag = modified;
      await this.writeFile(metapath, JSON.stringify(metadata, true, 2), 'application/json');
      const paths = core.traversePath(pathname);
      await Promise.all(
        paths.map(async ({ currentPath, upperBasename }) => {
          const currentMeta = await this.readMeta(username, currentPath);
          currentMeta.ETag = modified;
          currentMeta.items[path.basename(currentPath) + '/'] = { ETag: modified };
          await this.writeFile(this._metaPath(username, currentPath), JSON.stringify(currentMeta, true, 2), 'application/json');
        }));
      return { created, modified, conflict: false };
    } catch (error) {
      return { created: false, conflict: false };
    }
  }

  async delete (username, pathname, version) {
    const datapath = this.dataPath(username, pathname);
    const basename = decodeURI(path.basename(pathname));
    const metapath = this._metaPath(username, pathname);

    const metadata = await this.readMeta(username, pathname);
    if (!metadata || !metadata.items[basename]) {
      return { deleted: false, conflict: version };
    }
    // check if version matches when specified
    if (version) {
      if ((!metadata.items || !metadata.items[basename]) ||
        (metadata.items[basename].ETag !== version.replace(/"/g, ''))
      ) {
        return { deleted: false, conflict: true };
      }
    }

    const itemVersion = metadata.items[basename].ETag;
    try {
      // remove file and update metadata
      await this.deleteObject(datapath);
      delete metadata.items[basename];
      metadata.ETag = Date.now().toString();
      await this.writeFile(metapath, JSON.stringify(metadata, true, 2), 'application/json');

      // update all parents
      const paths = core.traversePath(pathname);
      let upperMeta = metadata;
      const tasks = paths.map(({ currentPath, upperBasename }) => async () => {
        // read current metadata
        let currentMeta = await this.readMeta(username, currentPath);
        // remove folder from upper folder in case this is empty
        if (Object.keys(upperMeta.items).length === 0) {
          delete currentMeta.items[path.basename(currentPath) + '/'];
          currentMeta.ETag = metadata.ETag;
          await this.writeFile(this._metaPath(username, currentPath), JSON.stringify(currentMeta, true, 2), 'application/json');
        }
        upperMeta = currentMeta;
      });

      // resolve these promises sequentially (delete upper dir first)
      await tasks.reduce((promise, task) => {
        return promise.then(result => task().then(Array.prototype.concat.bind(result)));
      }, Promise.resolve([]));
    } catch (e) {
      return { deleted: false };
    }
    return { modified: itemVersion, deleted: true };
  }

  // TODO use traversePath insteads
  async _updateParents (username, pathname, modified) {
    const parents = core.parents(pathname, false);
    for (let i = 1; i < parents.length; i++) {
      const metapath = this._metaPath(username, parents[i], true);
      const metadata = await this.readMeta(username, parents[i], true);
      const basepath = path.basename(parents[i - 1]) + '/';
      metadata.ETag = modified;
      metadata.items[basepath] = { ETag: modified };
      await this.writeFile(metapath, JSON.stringify(metadata, true, 2), 'application/json');
    }
  }
}

module.exports = DigitalOceanSpaces;
