import js from '@eslint/js';
import tseslint from 'typescript-eslint';
export default tseslint.config(
  { ignores: ['node_modules', 'data'] },
  {
    languageOptions: {
      globals: {
        document: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        fetch: 'readonly',
        location: 'readonly',
      },
    },
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
);
