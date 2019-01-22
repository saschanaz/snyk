module.exports = applyPatch;

var debug = require('debug')('snyk');
var diff = require('diff');
var exec = require('child_process').exec;
var path = require('path');
var fs = require('fs');
var errorAnalytics = require('../analytics').single;

function applyPatch(patch, vuln, live) {
  var cwd = vuln.source;

  return new Promise(function (resolve, reject) {
    if (!cwd) {
      cwd = process.cwd();
    }

    var relative = path.relative(process.cwd(), cwd);
    debug('DRY RUN: relative: %s', relative);

    try {
      var packageJson = fs.readFileSync(path.resolve(relative, 'package.json'));
      var pkg = JSON.parse(packageJson);
      debug('package at patch target location: %s@%s', pkg.name, pkg.version);
    } catch (err) {
      debug('Failed loading package.json of package about to be patched', err);
    }

    var patchContent = fs.readFileSync(path.resolve(relative, patch), 'utf8');

    jsDiff(patchContent, cwd, relative, true).then(function () {
      if (live) {
        return jsDiff(patchContent, cwd, relative, false);
      }
    }).then(function () {
      debug('patch succeed');
      resolve();
    }).catch(function (error) {
      debug('patch command failed', relative, error);
      patchError(error, relative, vuln).catch(reject);
    });
  });
}

function jsDiff(patchContent, cwd, relative, dryRun) {
  return new Promise(function (resolve, reject) {
    diff.applyPatches(patchContent, {
      loadFile: function (index, callback) {
        try {
          var fileName = stripFirstSlash(index.oldFileName);
          var content;
          try {
            content = fs.readFileSync(path.resolve(relative, fileName), 'utf8');
          } catch (err) {
            throw new Error(cwd + '\n' + relative + '\n' + index.oldFileName + '\n' + fileName);
          }
          callback(null, content);
        } catch (err) {
          callback(err);
        }
      },
      patched: function (index, content, callback) {
        try {
          if (content === false) {
            throw new Error('A patch hunk didn\'t fit anywhere');
          }
          if (!dryRun) {
            var newFileName = stripFirstSlash(index.newFileName);
            var oldFileName = stripFirstSlash(index.oldFileName);
            if (newFileName !== oldFileName) {
              fs.unlinkSync(path.resolve(relative, oldFileName));
            }
            fs.writeFileSync(path.resolve(relative, newFileName), content);
          }
          callback();
        } catch (err) {
          callback(err);
        }
      },
      complete: function (error) {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      },
    });
  });
}

function stripFirstSlash(fileName) {
  return fileName.replace(/^[^\/]+\//, '');
}

function patchError(error, dir, vuln) {
  if (error && error.code === 'ENOENT') {
    error.message = 'Failed to patch: the target could not be found.';
    return Promise.reject(error);
  }

  return new Promise(function (resolve, reject) {
    var id = vuln.id;

    exec('npm -v', {
      env: process.env,
    }, function (patchVError, versions) { // stderr is ignored
      var parts = versions.split('\n');
      var npmVersion = parts.shift();

      // post the raw error to help diagnose
      errorAnalytics({
        command: 'patch-fail',
        metadata: {
          from: vuln.from.slice(1),
          vulnId: id,
          packageName: vuln.name,
          packageVersion: vuln.version,
          package: vuln.name + '@' + vuln.version,
          error: error,
          'npm-version': npmVersion,
        },
      });

      // this is a general "patch failed", since we already check if the
      // patch was applied via a flag, this means something else went
      // var filename = path.relative(process.cwd(), dir);
      // error = new Error('"' + filename + '" (' + id + ')');
      // error.code = 'FAIL_PATCH';
      // wrong, so we'll ask the user for help to diagnose.

      reject(error);
    });
  });
}
