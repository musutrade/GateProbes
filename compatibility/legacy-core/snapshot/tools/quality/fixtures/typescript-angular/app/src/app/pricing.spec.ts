import { TestBed } from '@angular/core/testing';
import { Pricing } from './pricing';

describe('Pricing', () => {
  it('quotes a small order', () => {
    expect(TestBed.inject(Pricing).quote(2)).toBe(20);
  });
});
