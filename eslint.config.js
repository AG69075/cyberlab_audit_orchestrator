const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  { ignores: ['node_modules/'] },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      sourceType: 'commonjs',
      ecmaVersion: 2023,
      globals: { ...globals.node },
    },
    rules: {
      // app.js contient des signatures d'octets volontaires (ex. en-tête ZIP,
      // .DS_Store) dans des regex : le contrôle est un faux positif ici.
      'no-control-regex': 'off',
    },
  },
];
