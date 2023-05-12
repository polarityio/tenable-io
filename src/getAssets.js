const { map, get, size } = require('lodash/fp');
const { polarityRequest } = require('./polarity-request');
const { getLogger } = require('./logger');

async function getAssets(entities) {
  const Logger = getLogger();
  let vulnerabilities = [];

  const requestOptions = map(
    (entity) => ({
      entity,
      method: 'GET',
      path: `/workbenches/assets?filter.0.filter=host.target&filter.0.quality=eq&filter.0.value=${entity.value}`
    }),
    entities
  );

  const response = await polarityRequest.send(requestOptions);

  const asset = get('0.result.body.assets.0', response) || [];
  const entity = get('0.entity', response) || [];

  if (size(asset) > 0) {
    vulnerabilities = await getVulnerabilitiesForAsset(asset);
  }

  return {
    entity,
    asset,
    vulnerabilities: vulnerabilities
  };
}

async function getVulnerabilitiesForAsset(asset) {
  const queryRequestOptions = {
    method: 'GET',
    path: `/workbenches/assets/${asset.id}/vulnerabilities`
  };

  const assetsWithVulnerabilities = await polarityRequest.send(queryRequestOptions);

  return {
    vulnerabilities:
      get('0.result.body.vulnerabilities', assetsWithVulnerabilities) || [],
    total_vulnerability_count:
      get('0.result.body.total_vulnerability_count', assetsWithVulnerabilities) || 0
  };
}

module.exports = getAssets;
