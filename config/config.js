module.exports = {
  name: 'tenable.io',
  acronym: 'TNIO',
  description: '',
  entityTypes: ['*'],
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
    level: 'trace' //trace, debug, info, warn, error, fatal
  },
  options: [
    {
      key: 'url',
      name: 'TenableIO Url',
      description: 'Url for TenableIo instance.',
      default: 'https://cloud.tenable.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'accessKey',
      name: 'Access Key',
      description:
        'The Tenable io access key generated in Tenable io user dashboard. https://docs.tenable.com/tenableio/Content/Platform/Settings/MyAccount/GenerateAPIKey.htm',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'secretKey',
      name: 'Secret Key',
      description:
        'The tenable io secret key generated in the Tenable io user dashboard.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
