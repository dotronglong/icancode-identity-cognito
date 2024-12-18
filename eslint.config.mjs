// @ts-check

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  ...tseslint.configs.stylistic,
  {
    ignores: [
      '**/dist/**',
      'src/lambda.ts',
      'src/event.ts',
      '**.js',
      'test/__mocks__/**',
    ],
  },
  {
    rules: {
      'max-len': ['error', { code: 100 }],
      '@typescript-eslint/no-explicit-any': 'off',
    },
  }
);
