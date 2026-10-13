import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { App } from './app';
import { routes } from './app.routes';

it('renders the external template', async () => {
  TestBed.configureTestingModule({ providers: [provideRouter(routes)] });
  const fixture = TestBed.createComponent(App);
  await fixture.whenStable();
  expect(fixture.nativeElement.textContent).toContain('Small order: 20');
});

it('loads the lazy route', async () => {
  TestBed.configureTestingModule({ providers: [provideRouter(routes)] });
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl('/details');
  expect(harness.routeNativeElement?.textContent).toContain('Provider contract');
});
