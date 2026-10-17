import { useState, type ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';

const LINKS = {
 repository: 'https://github.com/axinlab71/devin-account-manager',
 issues: 'https://github.com/axinlab71/devin-account-manager/issues',
 releases: 'https://github.com/axinlab71/devin-account-manager/releases',
 upstream: 'https://github.com/jlcodes99/cockpit-tools',
};

export function ProjectLink({ destination, children }: { destination: keyof typeof LINKS; children: ReactNode }) {
 const [error, setError] = useState('');
 return <><a href={LINKS[destination]} target="_blank" rel="noreferrer" onClick={event => {
  if ('__TAURI_INTERNALS__' in window) {
   event.preventDefault(); setError('');
   void invoke('open_project_link', { destination }).catch(e => setError(String(e)));
  }
 }}>{children}</a>{error && <span className="error" role="alert">{error}：{LINKS[destination]}</span>}</>;
}
