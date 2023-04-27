const { map } = require('lodash/fp');
const { polarityRequest } = require('./polarity-request');
const { getLogger } = require('./logger');

async function getAssets(entities) {
  const Logger = getLogger();

  const requestOptions = map(
    (entity) => ({
      entity,
      method: 'GET',
      path: `/workbenches/assets?filter.0.filter=host.target&filter.0.quality=eq&filter.0.value=${entity.value}`
    }),
    entities
  );
  Logger.trace({ requestOptions }, 'Query Request Options');

  const response = await polarityRequest.send(requestOptions);
  Logger.trace({ response }, 'Query Response');

  const asset = response[0].result.body.assets[0];
  const entity = response[0].entity;

  const vulnerabilities = await getVulnerabilitiesForAsset(asset, entity);
  Logger.trace({ vulnerabilities }, 'Vulnerabilities');

  return {
    entity,
    asset,
    vulnerabilities: vulnerabilities
  };
}

async function getVulnerabilitiesForAsset(asset) {
  const Logger = getLogger();

  Logger.trace({ asset }, 'getVulnerabilitiesForAsset asset');

  const queryRequestOptions = {
    method: 'GET',
    path: `/workbenches/assets/${asset.id}/vulnerabilities`
  };

  const assetsWithVulnerabilities = await polarityRequest.send(queryRequestOptions);

  return {
    vulnerabilities: assetsWithVulnerabilities[0].result.body.vulnerabilities,
    total_vulnerability_count:
      assetsWithVulnerabilities[0].result.body.total_vulnerability_count
  };
}

module.exports = getAssets;
