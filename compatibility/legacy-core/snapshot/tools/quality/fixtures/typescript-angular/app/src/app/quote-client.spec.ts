import { fetchQuote } from './quote-client';

it('consumes the real Rust provider through the generated contract', async () => {
  const url = process.env['REFERENCE_PROVIDER_URL'];
  if (!url) throw new Error('Run collect.py to start the required Rust provider');
  expect(await fetchQuote(url)).toEqual({ amount: 42, currency: 'USD' });
});
