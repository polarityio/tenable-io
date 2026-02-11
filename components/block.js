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
  defaultSeverityFilters() {
    return {
      critical: true,
      high: true,
      medium: true,
      low: true,
      info: false
    };
  },
  details: Ember.computed.alias('block.data.details'),
  isCveEntity: Ember.computed('details.isCveEntity', 'block.entity', function () {
    if (this.get('details.isCveEntity') === true) {
      return true;
    }

    const entity = this.get('block.entity') || {};

    if (entity.type && entity.type.toLowerCase() === 'cve') {
      return true;
    }
    if (entity.value && /^cve-\d{4}-\d+$/i.test(entity.value)) {
      return true;
    }
    return false;
  }),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  vulnerabilities: Ember.computed.alias('details.vulnerabilities'),
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
  normalizeVulnerabilities(vulnerabilities) {
    return (vulnerabilities || [])
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
  },
  buildSeverityPercentages(normalized) {
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
        total > 0 ? Number(((counts[key].count / total) * 100).toFixed(2)) : 0;
    });

    return counts;
  },
  filterVulnerabilities(normalized, filters) {
    return (normalized || []).filter((vuln) => {
      const className = (vuln._severityMeta && vuln._severityMeta.className) || 'info';

      return filters[className];
    });
  },
  buildSelectedSeverityMessage(filters) {
    const labels = this.get('severityLevels')
      .filter((level) => filters[level.className])
      .map((level) => level.label);

    if (labels.length === 0) {
      return 'Showing 0 vulnerabilities (no severities selected)';
    }

    return `Showing vulnerabilities with severities: ${labels.join(', ')}`;
  },
  fetchVulnerabilitiesForAsset(asset) {
    if (!asset || !asset.id) {
      return;
    }
    if (asset._isLoadingVulnerabilities || asset._vulnerabilitiesLoaded) {
      return;
    }

    Ember.set(asset, '_isLoadingVulnerabilities', true);
    Ember.set(asset, '_vulnerabilitiesError', '');

    const payload = {
      action: 'GET_ASSET_VULNERABILITIES',
      assetId: asset.id
    };

    this.sendIntegrationMessage(payload)
      .then((result) => {
        if (result && result.error) {
          Ember.set(
            asset,
            '_vulnerabilitiesError',
            result.error.detail || 'Error retrieving vulnerabilities'
          );
          return;
        }
        if (result && result.data) {
          Ember.set(asset, '_vulnerabilities', result.data);
          Ember.set(asset, '_vulnerabilitiesLoaded', true);
        }
      })
      .catch((err) => {
        Ember.set(asset, '_vulnerabilitiesError', JSON.stringify(err, null, 2));
      })
      .finally(() => {
        Ember.set(asset, '_isLoadingVulnerabilities', false);
      });
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
  assets: Ember.computed('details.assets', 'details.asset', function () {
    const assets = this.get('details.assets');
    if (Array.isArray(assets) && assets.length > 0) {
      return assets;
    }
    const asset = this.get('details.asset');
    return asset ? [asset] : [];
  }),
  assetsWithVulnData: Ember.computed(
    'assets.[]',
    'assets.@each._vulnerabilities',
    'assets.@each._vulnerabilitiesLoaded',
    'assets.@each._filterCritical',
    'assets.@each._filterHigh',
    'assets.@each._filterMedium',
    'assets.@each._filterLow',
    'assets.@each._filterInfo',
    'details.vulnerabilities',
    'isCveEntity',
    function () {
      const assets = this.get('assets') || [];
      const isCveEntity = this.get('isCveEntity');
      const defaultVulnerabilities = isCveEntity ? null : this.get('details.vulnerabilities');

      return assets.map((asset) => {
        const defaultFilters = this.defaultSeverityFilters();
        if (typeof asset._filterCritical === 'undefined') {
          Ember.set(asset, '_filterCritical', defaultFilters.critical);
        }
        if (typeof asset._filterHigh === 'undefined') {
          Ember.set(asset, '_filterHigh', defaultFilters.high);
        }
        if (typeof asset._filterMedium === 'undefined') {
          Ember.set(asset, '_filterMedium', defaultFilters.medium);
        }
        if (typeof asset._filterLow === 'undefined') {
          Ember.set(asset, '_filterLow', defaultFilters.low);
        }
        if (typeof asset._filterInfo === 'undefined') {
          Ember.set(asset, '_filterInfo', defaultFilters.info);
        }

        const filters = {
          critical: asset._filterCritical,
          high: asset._filterHigh,
          medium: asset._filterMedium,
          low: asset._filterLow,
          info: asset._filterInfo
        };
        const vulnerabilitiesData = isCveEntity ? asset._vulnerabilities : defaultVulnerabilities;
        const vulnerabilityList =
          (vulnerabilitiesData && vulnerabilitiesData.vulnerabilities) || [];
        const normalized = this.normalizeVulnerabilities(vulnerabilityList);
        const filtered = this.filterVulnerabilities(normalized, filters);
        const severityPercentages = this.buildSeverityPercentages(normalized);

        Ember.set(asset, '_normalizedVulnerabilities', normalized);
        Ember.set(asset, '_filteredVulnerabilities', filtered);
        Ember.set(asset, '_severityPercentages', severityPercentages);
        Ember.set(asset, '_selectedSeverityMessage', this.buildSelectedSeverityMessage(filters));
        Ember.set(asset, '_vulnerabilitiesLoaded', isCveEntity ? !!asset._vulnerabilities : true);
        if (typeof asset._showVulnerabilityDetails === 'undefined') {
          Ember.set(asset, '_showVulnerabilityDetails', false);
        }
        if (typeof asset._showVulnerabilityInfo === 'undefined') {
          Ember.set(asset, '_showVulnerabilityInfo', isCveEntity ? false : true);
        }
        return asset;
      });
    }
  ),
  init() {
    this._super(...arguments);
    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));
  },
  actions: {
    toggleVulnerabilityInfo(asset) {
      if (!asset) {
        return;
      }
      const isOpen = !!asset._showVulnerabilityInfo;
      Ember.set(asset, '_showVulnerabilityInfo', !isOpen);
      if (!isOpen) {
        if (this.get('isCveEntity')) {
          this.fetchVulnerabilitiesForAsset(asset);
        }
      }
    },
    toggleVulnerabilityDetails(asset) {
      if (!asset) {
        return;
      }
      Ember.set(asset, '_showVulnerabilityDetails', !asset._showVulnerabilityDetails);
    },
    toggleSeverityFilter(asset, severityKey) {
      if (!asset) {
        return;
      }
      const keyMap = {
        critical: '_filterCritical',
        high: '_filterHigh',
        medium: '_filterMedium',
        low: '_filterLow',
        info: '_filterInfo'
      };
      const prop = keyMap[severityKey];
      if (!prop) {
        return;
      }
      Ember.set(asset, prop, !asset[prop]);
    },
    copyData: function () {
      const savedSettings = {
        assets: (this.get('assetsWithVulnData') || []).map((asset) => ({
          asset,
          showVulnerabilityDetails: asset._showVulnerabilityDetails,
          showVulnerabilityInfo: asset._showVulnerabilityInfo
        }))
      };
      (this.get('assetsWithVulnData') || []).forEach((asset) => {
        Ember.set(asset, '_showVulnerabilityDetails', true);
        if (this.get('isCveEntity')) {
          Ember.set(asset, '_showVulnerabilityInfo', true);
        }
      });
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
    (savedSettings.assets || []).forEach((entry) => {
      Ember.set(entry.asset, '_showVulnerabilityDetails', entry.showVulnerabilityDetails);
      Ember.set(entry.asset, '_showVulnerabilityInfo', entry.showVulnerabilityInfo);
    });
    this.set('showCopyMessage', true);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
