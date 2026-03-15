import { initTheme } from './core/theme.js';
import { trackVisit } from './core/tracker.js';

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    trackVisit();
});
