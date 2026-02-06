import { validateBaseline } from './src/index.ts';

const validBaseline = {
  name: 'Test Baseline',
  title: 'Test Baseline Title',
  version: '1.0.0',
  checksum: {
    algorithm: 'sha256',
    value: 'abc123'
  },
  requirements: []
};

const result = validateBaseline(validBaseline);
console.log('Valid:', result.valid);
console.log('Errors:', JSON.stringify(result.errors, null, 2));
console.log('Error message:', result.getErrorMessage());
