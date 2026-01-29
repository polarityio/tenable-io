const { map, get, size } = require('lodash/fp');
const { polarityRequest } = require('./polarity-request');
const { getLogger } = require('./logger');

const severity_rank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
  info: 0
};

function getSeverityRank(vuln) {
  if (typeof vuln.severity === 'number') {
    return vuln.severity;
  }

  const label = (vuln.severity_label || '').toString().toLowerCase();
  if (label && severity_rank.hasOwnProperty(label)) {
    return severity_rank[label];
  }

  return -1;
}

function shouldIncludeAsset(vulnerabilities, minSeverityValue) {
  if (!minSeverityValue || minSeverityValue === 'none') {
    return true;
  }

  const minRank = severity_rank[minSeverityValue.toLowerCase()];
  if (typeof minRank !== 'number') {
    return true;
  }

  return vulnerabilities.some((vuln) => {
    const rank = getSeverityRank(vuln);
    return typeof rank === 'number' && rank >= minRank;
  });
}

async function getAssets(entities, options = {}) {
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

  const minSeverityValue = get('minVulnerabilitySeverity.value', options);
  const vulnList = get('vulnerabilities', vulnerabilities) || [];
  const includeAsset = shouldIncludeAsset(vulnList, minSeverityValue);

  return {
    entity,
    asset: includeAsset ? asset : [],
    vulnerabilities: includeAsset
      ? vulnerabilities
      : { vulnerabilities: [], total_vulnerability_count: 0 }
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
