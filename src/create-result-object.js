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

  createResultsObject(apiResponse) {
    const Logger = getLogger();
    Logger.trace({ apiResponse }, 'createResultObject arguments');

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

  createNoResultsObject() {
    return {
      entity: this.entity,
      data: null
    };
  }
}

module.exports = new PolarityResult();
