import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: 'details', loadComponent: () => import('./details/details').then(m => m.Details) },
];
