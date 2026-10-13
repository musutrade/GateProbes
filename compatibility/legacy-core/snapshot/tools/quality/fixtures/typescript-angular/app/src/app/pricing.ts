import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class Pricing {
  quote(quantity: number): number {
    if (quantity < 0) {
      throw new Error('Quantity must be nonnegative'); // Deliberately untested.
    }
    if (quantity >= 10) {
      return quantity * 8; // Deliberately untested discount branch.
    }
    return quantity * 10;
  }
}
