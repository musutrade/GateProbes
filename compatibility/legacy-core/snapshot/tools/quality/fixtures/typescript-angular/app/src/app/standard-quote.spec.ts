import { StandardQuote } from './standard-quote';
import { PriorityQuote } from './priority-quote';

it('keeps same-named methods on distinct classes', () => {
  expect(new StandardQuote().quote()).toBe(42);
  expect(new PriorityQuote().quote()).toBe(84);
});
