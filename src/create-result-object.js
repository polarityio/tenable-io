const { size } = require('lodash/fp');
const { getLogger } = require('./logger');
/**
 * Return a Result Object or a Result Miss Object based on the REST API response.
 * @param null || {entity, result}
 * if I pass nothing in, I want it to return a result object with no data
 * if i pass in a single object, I want it to return a result object with data
 * either pass in a single object or an array of objects, being
 * @returns {{data: null, entity}|{data: {summary: [string], details}, entity}}
 */
class PolarityResult {
  createEmptyBlock(entity) {
    return {
      entity: entity,
      data: {
        summary: ['Select a Category'],
        details: []
      }
    };
  }

  buildResults(apiResponse) {
    const Logger = getLogger();

    Logger.trace({ apiResponse }, 'buildResults arguments');

    const responses = Array.isArray(apiResponse) ? apiResponse : [apiResponse];

    return responses.map((response) => {
      if (size(response.assets || response.asset) === 0) {
        return this.createNoResultsObject(response);
      }
      return this.createResultsObject(response);
    });
  }

  createResultsObject(apiResponse) {
    const total_vulnerability_count =
      apiResponse.total_vulnerability_count ||
      apiResponse.vulnerabilities?.total_vulnerability_count ||
      apiResponse.asset?.vulnerabilities?.total_vulnerability_count ||
      0;
    const total_asset_count =
      apiResponse.total_asset_count ||
      (Array.isArray(apiResponse.assets) ? apiResponse.assets.length : 0);
    const assetCount =
      Array.isArray(apiResponse.assets) && apiResponse.assets.length > 0
        ? apiResponse.assets.length
        : 0;
    const summaryLabel = assetCount > 1 ? 'Assets' : 'Vulnerabilities';
    const summaryValue = assetCount > 1 ? total_asset_count : total_vulnerability_count;

    return {
      entity: apiResponse.entity,
      data: {
        summary: [`${summaryLabel}: ${summaryValue}`],
        details: apiResponse
      }
    };
  }

  createNoResultsObject(apiResponse) {
    return {
      entity: apiResponse.entity,
      data: null
    };
  }
}

module.exports = new PolarityResult();
