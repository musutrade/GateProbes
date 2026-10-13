import { Component, inject } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { Pricing } from './pricing';
import { StandardQuote } from './standard-quote';
import { PriorityQuote } from './priority-quote';

@Component({
  selector: 'app-root',
  imports: [RouterLink, RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  protected readonly amount = inject(Pricing).quote(2);
  protected readonly standard = new StandardQuote().quote();
  protected readonly priority = new PriorityQuote().quote();
}
