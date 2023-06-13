module.exports = {
  name: 'Tenable.io',
  acronym: 'TEN',
  description:
    'Search for assets in Tenable.io by IP Address or Domain and view vulnerability information.',
  entityTypes: ['IPv4', 'IPv6', 'domain'],
  styles: ['./styles/styles.less'],
  defaultColor: 'light-blue',
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  request: {
    cert: '',
    key: '',
    passphrase: '',
    ca: '',
    proxy: '',
    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  options: [
    {
      key: 'accessKey',
      name: 'Access Key',
      description:
        'The Tenable.io access key generated in Tenable io user dashboard.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'secretKey',
      name: 'Secret Key',
      description:
        'The Tenable.io secret key generated in the Tenable.io user dashboard.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
