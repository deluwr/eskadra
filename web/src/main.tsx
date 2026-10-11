import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';
import { getLang, startI18n } from './i18n';

// перевод включается до первой отрисовки: на английском текст заменяется сразу, без мигания русского
startI18n(getLang());

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
