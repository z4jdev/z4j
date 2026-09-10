import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { FormField } from "./form-field";
import {
  CONDITION_FIELDS,
  type GuidedConditions,
} from "@/lib/automation-builder";

export function AutomationBuilder({
  conditions,
  action,
  onConditionsChange,
  onActionChange,
}: {
  conditions: GuidedConditions;
  action: string;
  onConditionsChange: (text: string) => void;
  onActionChange: (text: string) => void;
}) {
  function setCondition(key: string, value: string) {
    const next = { ...conditions };
    if (value) next[key] = value;
    else delete next[key];
    onConditionsChange(JSON.stringify(next, null, 2));
  }
  return (
    <div className="space-y-4 rounded-lg border bg-muted/30 p-4">
      <div>
        <h3 className="text-sm font-semibold">Match all conditions</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          Leave a field empty to match any value. With no conditions, every
          event of the selected trigger matches.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {CONDITION_FIELDS.map(([key, label]) => (
          <FormField key={key} label={label}>
            <Input
              value={conditions[key] ?? ""}
              onChange={(e) => setCondition(key, e.target.value)}
              placeholder="Any"
            />
          </FormField>
        ))}
      </div>
      <FormField label="Then take this action">
        <Select
          value={action}
          onValueChange={(v) =>
            onActionChange(JSON.stringify([{ type: v }], null, 2))
          }
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="notify">
              Notify through matching notification subscriptions
            </SelectItem>
            <SelectItem value="retry">
              Retry the task · admin required
            </SelectItem>
            <SelectItem value="cancel">
              Cancel the task · admin required
            </SelectItem>
          </SelectContent>
        </Select>
      </FormField>
    </div>
  );
}
