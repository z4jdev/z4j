import {
  Children,
  cloneElement,
  isValidElement,
  useId,
  type ReactNode,
  type ReactElement,
} from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { SelectTrigger } from "@/components/ui/select";

/** Labels and descriptions reach the actual control, including a nested SelectTrigger. */
export function FormField({
  label,
  error,
  hint,
  children,
}: {
  label: string;
  error?: string;
  hint?: string;
  children: ReactNode;
}) {
  const id = useId();
  const descriptionId = `${id}-description`;
  function labelControls(nodes: ReactNode): ReactNode {
    return Children.map(nodes, (node) => {
      if (!isValidElement(node)) return node;
      const element = node as ReactElement<{
        children?: ReactNode;
        id?: string;
        "aria-describedby"?: string;
        "aria-invalid"?: boolean;
      }>;
      if (
        element.type === Input ||
        element.type === Textarea ||
        element.type === SelectTrigger
      ) {
        return cloneElement(element, {
          id,
          "aria-describedby": error || hint ? descriptionId : undefined,
          "aria-invalid": !!error,
        });
      }
      if (element.props.children)
        return cloneElement(element, {
          children: labelControls(element.props.children),
        });
      return element;
    });
  }
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {labelControls(children)}
      {(error || hint) && (
        <p
          id={descriptionId}
          role={error ? "alert" : undefined}
          className={
            error ? "text-sm text-destructive" : "text-xs text-muted-foreground"
          }
        >
          {error || hint}
        </p>
      )}
    </div>
  );
}
