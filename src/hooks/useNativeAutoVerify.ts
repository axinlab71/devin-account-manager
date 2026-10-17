import { useEffect, useRef } from 'react';
import { verifyNativeLogin, type NativeVerifyResult } from '../services/windsurfService';

// Read-only, serial checks. Closing the view or changing operations cancels
// updates; a timeout never dismisses the backend's pending switch record.
export function useNativeAutoVerify(key: string | undefined, targetId: string | undefined,
 active: boolean, onResult: (result: NativeVerifyResult) => void) {
 const callback = useRef(onResult);
 callback.current = onResult;
 useEffect(() => {
  if (!active || !key || !targetId) return;
  let cancelled = false;
  let timer: ReturnType<typeof setTimeout>;
  const deadline = performance.now() + 45_000;
  const check = async () => {
   try {
    const result = await verifyNativeLogin(targetId);
    if (cancelled) return;
    callback.current(result);
    // A transient network failure is not a completed check. Keep the
    // bounded polling window open; explicit rejection still stops polling.
    if (result.state === 'verified' && result.remoteStatus !== 'unavailable') return;
   } catch { /* Manual verification remains available after transient errors. */ }
   if (!cancelled && performance.now() < deadline) timer = setTimeout(() => void check(), 1500);
  };
  timer = setTimeout(() => void check(), 700);
  return () => { cancelled = true; clearTimeout(timer); };
 }, [key, targetId, active]);
}
