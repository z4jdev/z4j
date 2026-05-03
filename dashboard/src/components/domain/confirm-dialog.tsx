/**
 * A tiny async confirm-dialog hook backed by our shadcn Dialog primitive.
 *
 * Drop-in replacement for `window.confirm(...)`. Usage:
 *
 *   const { confirm, dialog } = useConfirm();
 *   // ...
 *   {dialog}
 *   <Button onClick={() =>
 *     confirm({
 *       title: "Delete channel",
 *       description: <>This removes <code>{name}</code>.</>,
 *       onConfirm: () => mutation.mutate(id),
 *     })
 *   } />
 *
 * Only one confirm is in-flight at a time; calling `confirm()` again
 * replaces the previous state.
 */
import { useCallback, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface ConfirmState {
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: "destructive" | "default";
  onConfirm: () => void | Promise<void>;
}

export function useConfirm() {
  const [state, setState] = useState<ConfirmState | null>(null);
  const [pending, setPending] = useState(false);

  const confirm = useCallback((s: ConfirmState) => {
    setState(s);
    setPending(false);
  }, []);

  const close = useCallback(() => {
    setState(null);
    setPending(false);
  }, []);

  const handleConfirm = useCallback(async () => {
    if (!state) return;
    try {
      setPending(true);
      await state.onConfirm();
      setState(null);
    } finally {
      setPending(false);
    }
  }, [state]);

  const dialog = (
    <Dialog open={state !== null} onOpenChange={(o) => !o && !pending && close()}>
      <DialogContent>
        {state && (
          <>
            <DialogHeader>
              <DialogTitle>{state.title}</DialogTitle>
              <DialogDescription>{state.description}</DialogDescription>
            </DialogHeader>
            <DialogFooter className="mt-2">
              <Button
                type="button"
                variant="outline"
                onClick={close}
                disabled={pending}
              >
                {state.cancelLabel ?? "Cancel"}
              </Button>
              <Button
                type="button"
                variant={state.variant ?? "destructive"}
                onClick={handleConfirm}
                disabled={pending}
              >
                {pending ? "Working..." : (state.confirmLabel ?? "Confirm")}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );

  return { confirm, dialog };
}
