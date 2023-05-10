polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  vulnerabilities: Ember.computed('details.vulnerabilities', function () {
    return this.get('details.vulnerabilities');
  }),
  asset: Ember.computed('details.asset', function () {
    return this.get('details.asset');
  }),
  init() {
    this._super(...arguments);
    this.getVulnerabilitySeverityClass();
  },
  actions: {
    toggleVulnerabilityDetails() {
      this.toggleProperty('showVulnerabilityDetails');
    }
  },
  getVulnerabilitySeverityClass() {
    const vulnerabilities = this.get('vulnerabilities').vulnerabilities;

    let severityLevels = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    const severityMapping = {
      4: 'critical',
      3: 'high',
      2: 'medium',
      1: 'low',
      0: 'info'
    };

    vulnerabilities.forEach((vulnerability) => {
      const severityKey = severityMapping[vulnerability.severity];
      severityLevels[severityKey] += 1; // Increment the count by 1 for each vulnerability
    });

    // Calculate the total count
    const totalCount = Object.values(severityLevels).reduce((a, b) => a + b, 0);

    // Calculate the percentages
    const severityPercentages = Object.keys(severityLevels).reduce((acc, level) => {
      acc[level] = {
        count: severityLevels[level],
        percent: totalCount > 0 ? (severityLevels[level] / totalCount) * 100 : '0'
      };
      return acc;
    }, {});

    this.set('severityPercentages', severityPercentages);
  }
});
