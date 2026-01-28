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

function pickAssetLabelValue(value) {
  if (Array.isArray(value)) {
    const firstValue = value.find((entry) => entry);
    if (!firstValue) {
      return '';
    }
    return typeof firstValue === 'string' ? firstValue : String(firstValue);
  }

  if (!value) {
    return '';
  }

  return typeof value === 'string' ? value : String(value);
}

function getAssetTitle(asset, index) {
  if (!asset) {
    return `Asset ${index + 1}`;
  }

  const hostname = pickAssetLabelValue(asset.hostname);
  if (hostname) {
    return hostname;
  }

  const ipv4 = pickAssetLabelValue(asset.ipv4);
  if (ipv4) {
    return ipv4;
  }

  return `Asset ${index + 1}`;
}

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
    (entity) =>
      isCveEntity(entity)
        ? { entity, method: 'CVE' }
        : {
            entity,
            method: 'GET',
            path: `/workbenches/assets?filter.0.filter=host.target&filter.0.quality=eq&filter.0.value=${entity.value}`
          },
    entities
  );

  for (const req of requestOptions) {
    if (req.method === 'CVE') {
      const cveResult = await handleCveEntity(req.entity, options);
      if (cveResult) {
        return cveResult;
      }
      continue;
    }

    const response = await polarityRequest.send(req);
    const assets = get('0.result.body.assets', response) || [];
    const asset = get('0', assets) || [];
    const entity = get('entity', response) || req.entity;

    if (size(asset) > 0) {
      vulnerabilities = await getVulnerabilitiesForAsset(asset.id);
    }

    const minSeverityValue = get('minVulnerabilitySeverity.value', options);
    const vulnList = get('vulnerabilities', vulnerabilities) || [];
    const includeAsset = shouldIncludeAsset(vulnList, minSeverityValue);

    return {
      entity,
      asset: includeAsset ? asset : [],
      assets: includeAsset ? assets : [],
      isCveEntity: false,
      vulnerabilities: includeAsset
        ? vulnerabilities
        : { vulnerabilities: [], total_vulnerability_count: 0 }
    };
  }

  return {
    entity: entities[0],
    asset: [],
    isCveEntity: false,
    vulnerabilities: { vulnerabilities: [], total_vulnerability_count: 0 }
  };
}

async function getVulnerabilitiesForAsset(assetId) {
  const queryRequestOptions = {
    method: 'GET',
    path: `/workbenches/assets/${assetId}/vulnerabilities`
  };

  const assetsWithVulnerabilities = await polarityRequest.send(queryRequestOptions);

  return {
    vulnerabilities:
      get('0.result.body.vulnerabilities', assetsWithVulnerabilities) || [],
    total_vulnerability_count:
      get('0.result.body.total_vulnerability_count', assetsWithVulnerabilities) || 0
  };
}

function isCveEntity(entity) {
  return (
    (entity && entity.type && entity.type.toLowerCase() === 'cve') ||
    /^cve-\d{4}-\d+$/i.test(entity.value)
  );
}

function buildHostIdFilterPath(assetIds) {
  const filters = assetIds.map(
    (assetId, index) =>
      `filter.${index}.filter=host.id&filter.${index}.quality=eq&filter.${index}.value=${encodeURIComponent(
        assetId
      )}`
  );

  return `/workbenches/assets?${filters.join('&')}&filter.search_type=OR`;
}

async function handleCveEntity(entity, options) {
  const Logger = getLogger();

  Logger.trace({ entity }, 'CVE lookup start');

  const pluginResp = await polarityRequest.send({
    entity,
    method: 'GET',
    path: `/workbenches/vulnerabilities?filter.0.filter=plugin.attributes.cve.raw&filter.0.quality=eq&filter.0.value=${encodeURIComponent(
      entity.value
    )}`
  });
  Logger.trace({ pluginResp }, 'CVE plugin lookup response');

  const vulnerabilityEntry = get('0.result.body.vulnerabilities.0', pluginResp);
  const pluginId = get('plugin_id', vulnerabilityEntry);
  const total_vulnerability_count = get('count', vulnerabilityEntry) || 0;

  if (!pluginId) {
    Logger.trace({ entity }, 'No pluginId returned for CVE');
    return {
      entity,
      asset: [],
      assets: [],
      vulnerabilities: { vulnerabilities: [], total_vulnerability_count: 0 },
      total_asset_count: 0
    };
  }

  const assetsResp = await polarityRequest.send({
    entity,
    method: 'GET',
    path: `/workbenches/assets/vulnerabilities?filter.0.filter=plugin.id&filter.0.quality=eq&filter.0.value=${pluginId}`
  });
  Logger.trace({ assetsResp }, 'Assets by plugin response');

  const assets = get('0.result.body.assets', assetsResp) || [];
  const total_asset_count = get('0.result.body.total_asset_count', assetsResp) || assets.length;
  const assetIds = assets.map((asset) => asset.id).filter(Boolean);
  let assetDetails = [];

  if (assetIds.length > 0) {
    const assetDetailsResp = await polarityRequest.send({
      entity,
      method: 'GET',
      path: buildHostIdFilterPath(assetIds)
    });

    Logger.trace({ assetDetailsResp }, 'Asset details response');
    assetDetails = get('0.result.body.assets', assetDetailsResp) || [];
  }

  let resolvedAssets = assets;
  if (assetDetails.length > 0) {
    const assetDetailsById = assetDetails.reduce((acc, assetDetail) => {
      if (assetDetail && assetDetail.id) {
        acc[assetDetail.id] = assetDetail;
      }
      return acc;
    }, {});

    resolvedAssets = assets.map((asset) => {
      const resolvedAsset = assetDetailsById[asset.id]
        ? { ...asset, ...assetDetailsById[asset.id] }
        : asset;

      return resolvedAsset;
    });
  }
  resolvedAssets = resolvedAssets.map((asset, index) => ({
    ...asset,
    _assetTitle: getAssetTitle(asset, index)
  }));
  const asset = get('0', resolvedAssets) || [];

  return {
    entity,
    asset,
    assets: resolvedAssets,
      isCveEntity: true,
    vulnerabilities: { vulnerabilities: [], total_vulnerability_count },
    total_asset_count
  };
}

module.exports = { getAssets, getVulnerabilitiesForAsset };
