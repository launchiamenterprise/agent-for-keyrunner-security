const path = require('path');

module.exports = {
  entry: './agent.ts',
  target: 'node',
  mode: 'production',
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  externals: {
    // Not used by this agent — stub with empty object so no runtime require is needed
    '@azure/identity': 'var {}',
    '@azure/keyvault-secrets': 'var {}',
    '@google-cloud/secret-manager': 'var {}',
    'axios-ntlm': 'var {}',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'agent.js',
  },
};
