polarity.export = PolarityComponent.extend({
  uniqueIdPrefix: '',
  showCopyMessage: false,
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
    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));
    this.getVulnerabilitySeverityClass();
  },
  actions: {
    toggleVulnerabilityDetails() {
      this.toggleProperty('showVulnerabilityDetails');
    },
    copyData: function () {
      const savedSettings = {
        showVulnerabilityDetails: this.get('showVulnerabilityDetails'),
      };
      this.set('showVulnerabilityDetails', true);
      Ember.run.scheduleOnce(
          'afterRender',
          this,
          this.copyElementToClipboard,
          `tenableio-container-${this.get('uniqueIdPrefix')}`
      );

      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, savedSettings);
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
  },
  copyElementToClipboard (element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState (savedSettings) {
    this.set('showVulnerabilityDetails', savedSettings.showVulnerabilityDetails);
    this.set('showCopyMessage', true);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
