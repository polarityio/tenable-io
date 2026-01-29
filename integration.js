'use strict';

const { polarityRequest } = require('./src/polarity-request');
const polarityResult = require('./src/create-result-object');
const { parseErrorToReadableJSON } = require('./src/errors');
const { getLogger, setLogger } = require('./src/logger');
const getAssets = require('./src/getAssets');

let Logger = null;

const startup = (logger) => {
  Logger = logger;
  setLogger(Logger);
};

async function doLookup(entities, options, cb) {
  const Logger = getLogger();
  Logger.trace({ entities }, 'entities');

  polarityRequest.setOptions(options);
  polarityRequest.setHeader(
    'X-ApiKeys',
    `accessKey=${options.accessKey};secretKey=${options.secretKey}`
  );

  try {
    const results = await getAssets(entities, options);

    const lookupResults = polarityResult.buildResults(results);

    Logger.trace({ lookupResults }, 'lookup results');
    cb(null, lookupResults);
  } catch (error) {
    const errorAsPojo = parseErrorToReadableJSON(error);
    Logger.error({ error: errorAsPojo }, 'Error in doLookup');
    cb(errorAsPojo);
  }
}

function validateOptions(userOptions, cb) {
  const errors = [];

  if (
    typeof userOptions.url.value !== 'string' ||
    (typeof userOptions.url.value === 'string' &&
      userOptions.url.value.length === 0) ||
    !/^https?:\/\//i.test(userOptions.url.value)
  ) {
    errors.push({
      key: 'url',
      message:
        'You must provide a valid URL, which should start with http:// or https://'
    });
  }
  if (
    typeof userOptions.accessKey.value !== 'string' ||
    (typeof userOptions.accessKey.value === 'string' &&
      userOptions.accessKey.value.length === 0)
  ) {
    errors.push({
      key: 'accessKey',
      message:
        'You must provide an access key. You can find your access key in the Tenable.io UI under Settings -> My Account -> API Keys'
    });
  }
  if (
    typeof userOptions.secretKey.value !== 'string' ||
    (typeof userOptions.secretKey.value === 'string' &&
      userOptions.secretKey.value.length === 0)
  ) {
    errors.push({
      key: 'secretKey',
      message:
        'You must provide a secret key. You can find your secret key in the Tenable.io UI under Settings -> My Account -> API Keys'
    });
  }
  return cb(null, errors);
}

module.exports = {
  startup,
  validateOptions,
  doLookup
};
