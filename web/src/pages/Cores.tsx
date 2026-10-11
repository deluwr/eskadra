import { CoresPanel } from './Configs';

/** Ядра флота: версии на серверах, установка, обновление и откат. */
export function CoresPage() {
  return (
    <>
      <div className="page-head"><div><h1>Ядра</h1><p>Xray, sing-box и telemt на серверах: установка, обновление, откат</p></div></div>
      <CoresPanel />
    </>
  );
}
