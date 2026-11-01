import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';
import { getLang, startI18n } from './i18n';
import { applyFont, applyTheme, readFont, readTheme } from './theme';
import { startFitTables } from './fitTables';

// перевод и цветовая схема — до первой отрисовки: без мигания русского текста и чужих цветов
startI18n(getLang());
applyTheme(readTheme());
applyFont(readFont());
startFitTables();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
