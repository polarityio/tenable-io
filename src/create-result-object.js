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

    if (size(apiResponse.asset) === 0) {
      return this.createNoResultsObject(apiResponse);
    } else {
      Logger.trace({ apiResponse }, 'buildResults arguments');
      return this.createResultsObject(apiResponse);
    }
  }

  createResultsObject(apiResponse) {
    const total_vulnerability_count =
      apiResponse.vulnerabilities.total_vulnerability_count;

    return [
      {
        entity: apiResponse.entity,
        data: {
          summary: [`Vulnerabilities: ${total_vulnerability_count}`],
          details: apiResponse
        }
      }
    ];
  }

  createNoResultsObject(apiResponse) {
    return [
      {
        entity: apiResponse.entity,
        data: null
      }
    ];
  }
}

module.exports = new PolarityResult();
