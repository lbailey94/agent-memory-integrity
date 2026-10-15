#!/usr/bin/env node
'use strict';

/*
 * Narrow Node bridge from AGMI to the pinned Surgical DevOps G7 API.
 *
 * Genuine writes and verification go through SDO.  Raw attack writes never
 * come through this file; the Python adapter applies those directly to G7,
 * as required by the at-rest threat model.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const EXPECTED_COMMIT = 'f267cf38b0ac321b6361602973b4d34b5c043e1c';
const EXPECTED_NODE = 'v24.18.0';
const EXPECTED_PACKAGE_VERSION = '2.6.0-rc.6';

function sha(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function fail(message) {
  throw new Error(message);
}

function repositoryRoot(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    fail('AGMI_SDO_REPO must be an absolute path.');
  }
  const root = fs.realpathSync(value);
  const head = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim();
  if (head !== EXPECTED_COMMIT) {
    fail(`Surgical DevOps pin mismatch: expected ${EXPECTED_COMMIT}, found ${head}.`);
  }
  if (process.version !== EXPECTED_NODE) {
    fail(`Node pin mismatch: expected ${EXPECTED_NODE}, found ${process.version}.`);
  }
  const packageVersion = JSON.parse(
    fs.readFileSync(path.join(root, 'package.json'), 'utf8')
  ).version;
  if (packageVersion !== EXPECTED_PACKAGE_VERSION) {
    fail(`Surgical DevOps package mismatch: expected ${EXPECTED_PACKAGE_VERSION}, found ${packageVersion}.`);
  }
  return { root, head, packageVersion };
}

function modules(root) {
  return {
    boundary: require(path.join(root, 'accelerator/core/workspace-boundary')),
    core: require(path.join(root, 'accelerator/cli/natural-development-authorization-consumption')),
    store: require(path.join(root, 'accelerator/adapters/natural-development-authorization-consumption-store'))
  };
}

function immutableAuthorization(label) {
  return Object.freeze({
    authorizationFingerprint: sha(`agmi:sdo:g4:${label}`),
    singleUse: true,
    reusable: false,
    operationalAuthority: false,
    mutationAuthority: false,
    dispatchAuthority: false
  });
}

function createAndPersistClaim(api, input, index) {
  const observation = api.boundary.observePhysicalWorkspaceIdentity(input.workspaceRoot);
  const label = `${input.contextLabel}:${index}`;
  const claim = api.core.createNaturalDevelopmentAuthorizationClaim({
    authorization: immutableAuthorization(label),
    operationId: `agmi-sdo-operation:${label}`,
    physicalWorkspaceIdentity: observation.physicalWorkspaceIdentity,
    target: `agmi/${input.contextLabel}/memory-${index}.json`,
    beforeSha256: sha(`agmi:sdo:before:${label}`),
    replacementSha256: sha(`agmi:sdo:replacement:${label}`)
  });
  const receipt = api.store.claimNaturalDevelopmentAuthorization({
    stateRoot: input.stateRoot,
    claim
  });
  const persisted = api.store.loadNaturalDevelopmentAuthorizationConsumption({
    stateRoot: input.stateRoot,
    authorizationFingerprint: claim.authorizationFingerprint,
    readPurpose: api.store.READ_PURPOSE.CURRENT_AUTHORITY,
    expectedPhysicalWorkspaceIdentity: observation.physicalWorkspaceIdentity
  });
  return { claim, persisted, receipt, observation };
}

function dispatch(input) {
  const pin = repositoryRoot(input.sdoRepo);
  const api = modules(pin.root);
  switch (input.action) {
    case 'probe':
      return {
        commit: pin.head,
        node: process.version,
        packageVersion: pin.packageVersion
      };
    case 'observe':
      return api.boundary.observePhysicalWorkspaceIdentity(input.workspaceRoot);
    case 'seed': {
      const records = [];
      for (let index = 0; index < input.count; index += 1) {
        records.push(createAndPersistClaim(api, input, input.startIndex + index));
      }
      return records;
    }
    case 'verify': {
      try {
        for (const fingerprint of input.authorizationFingerprints) {
          const value = api.store.loadNaturalDevelopmentAuthorizationConsumption({
            stateRoot: input.stateRoot,
            authorizationFingerprint: fingerprint,
            readPurpose: api.store.READ_PURPOSE.CURRENT_AUTHORITY,
            expectedPhysicalWorkspaceIdentity: input.physicalWorkspaceIdentity
          });
          if (!value) {
            return { intact: false, detail: `SDO read returned no G7 record for ${fingerprint}.` };
          }
        }
        return { intact: true, detail: null };
      } catch (error) {
        return { intact: false, detail: `${error.name}: ${error.message}` };
      }
    }
    default:
      fail(`Unknown bridge action: ${input.action}`);
  }
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  try {
    const result = dispatch(JSON.parse(input));
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
});
