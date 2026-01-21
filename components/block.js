polarity.export = PolarityComponent.extend({
  uniqueIdPrefix: '',
  showCopyMessage: false,
  severityLevels: Object.freeze([
    { rank: 4, label: 'Critical', className: 'critical', aliases: ['critical'] },
    { rank: 3, label: 'High', className: 'high', aliases: ['high'] },
    { rank: 2, label: 'Medium', className: 'medium', aliases: ['medium'] },
    { rank: 1, label: 'Low', className: 'low', aliases: ['low'] },
    { rank: 0, label: 'Info', className: 'info', aliases: ['info', 'informational'] }
  ]),
  severityLookup: Ember.computed(function () {
    return this.get('severityLevels').reduce(
      (acc, level) => {
        acc.byRank[level.rank] = level;
        acc.byLabel[level.className] = level;
        level.aliases.forEach((alias) => (acc.byLabel[alias] = level));
        return acc;
      },
      { byRank: {}, byLabel: {} }
    );
  }),
  severityFilters: Ember.computed(function () {
    //Default: all severities on except informational
    return this.get('severityLevels').reduce((acc, level) => {
      acc[level.className] = level.className !== 'info';
      return acc;
    }, {});
  }),
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  vulnerabilities: Ember.computed('details.vulnerabilities', function () {
    return this.get('details.vulnerabilities');
  }),
  /**
   * Normalize severity label/class for a vulnerability entry.
   * Returns both the severity meta (for color/class) and the display label.
   */
  buildSeverityStats(vuln) {
    const { byRank, byLabel } = this.get('severityLookup');
    const severityLabelFromRank =
      typeof vuln.severity === 'number' && byRank[vuln.severity]
        ? byRank[vuln.severity].label
        : '';
    const severityLabel = vuln.severity_label || severityLabelFromRank || '';
    const normalizedKey = (severityLabel && severityLabel.toString().toLowerCase()) || '';
    const severityMeta =
      byLabel[normalizedKey] ||
      (typeof vuln.severity === 'number' ? byRank[vuln.severity] : undefined);
    const severityRank =
      (severityMeta && severityMeta.rank) ||
      (typeof vuln.severity === 'number' ? vuln.severity : -1);

    return {
      severityMeta,
      severityLabelDisplay:
        (severityMeta && severityMeta.label) || severityLabel || vuln.severity,
      severityRank: severityRank
    };
  },
  normalizedVulnerabilities: Ember.computed('details.vulnerabilities.vulnerabilities', function () {
    const vulnerabilities =
      (this.get('details.vulnerabilities') &&
        this.get('details.vulnerabilities').vulnerabilities) ||
      [];

    return vulnerabilities
      .map((vuln) => {
        const { severityMeta, severityLabelDisplay, severityRank } = this.buildSeverityStats(vuln);

        return Object.assign({}, vuln, {
          _severityMeta: severityMeta,
          _severityLabelDisplay: severityLabelDisplay,
          _severityRank: severityRank
        });
      })
      .sort((a, b) => {
        const rankA = typeof a._severityRank === 'number' ? a._severityRank : -1;
        const rankB = typeof b._severityRank === 'number' ? b._severityRank : -1;
        return rankB - rankA;
      });
  }),
  filteredVulnerabilities: Ember.computed(
    'normalizedVulnerabilities.[]',
    'severityFilters.critical',
    'severityFilters.high',
    'severityFilters.medium',
    'severityFilters.low',
    'severityFilters.info',
    function () {
      const filters = this.get('severityFilters') || {};

      return (this.get('normalizedVulnerabilities') || []).filter((vuln) => {
        const className = (vuln._severityMeta && vuln._severityMeta.className) || 'info';

        return filters[className];
      });
    }
  ),
  severityPercentages: Ember.computed('normalizedVulnerabilities.[]', function () {
    const normalized = this.get('normalizedVulnerabilities') || [];
    const counts = this.get('severityLevels').reduce((acc, level) => {
      acc[level.className] = { count: 0, percent: 0 };
      return acc;
    }, {});

    normalized.forEach((vuln) => {
      const className = (vuln._severityMeta && vuln._severityMeta.className) || 'info';
      if (!counts[className]) {
        counts[className] = { count: 0, percent: 0 };
      }
      counts[className].count += 1;
    });

    const total = normalized.length;
    Object.keys(counts).forEach((key) => {
      counts[key].percent =
        total > 0 ? ((counts[key].count / total) * 100).toFixed(2) : '0.00';
    });

    return counts;
  }),
  selectedSeverityMessage: Ember.computed(
    'severityFilters.critical',
    'severityFilters.high',
    'severityFilters.medium',
    'severityFilters.low',
    'severityFilters.info',
    function () {
      const filters = this.get('severityFilters') || {};
      const labels = this.get('severityLevels')
        .filter((level) => filters[level.className])
        .map((level) => level.label);

      if (labels.length === 0) {
        return 'Showing 0 vulnerabilities (no severities selected)';
      }

      return `Showing vulnerabilities with severities: ${labels.join(', ')}`;
    }
  ),
  asset: Ember.computed('details.asset', function () {
    return this.get('details.asset');
  }),
  init() {
    this._super(...arguments);
    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));
  },
  actions: {
    toggleVulnerabilityDetails() {
      this.toggleProperty('showVulnerabilityDetails');
    },
    toggleSeverityFilter(severityKey) {
      const current = this.get(`severityFilters.${severityKey}`);
      this.set(`severityFilters.${severityKey}`, !current);
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
