import { initTheme } from './core/theme.js';
import { trackVisit } from './core/tracker.js';
import { initClock } from './core/clock.js';

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    trackVisit();
    initClock();
});
