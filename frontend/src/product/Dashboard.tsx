import { useState } from "react";
import { useAccountScope } from "../lib/accountScope";
import { CnappOverview } from "./CnappOverview";
import { useDemoDashboardModel } from "./useDemoDashboardModel";
import { useProduct } from "./store";

function DemoAccountDashboard() {
  const model = useDemoDashboardModel();
  const { canAct, log, tenant, scope } = useProduct();
  const [message, setMessage] = useState<string | null>(null);

  return (
    <CnappOverview
      model={model}
      canScan={canAct}
      message={message}
      onRefresh={() =>
        setMessage("Demo snapshot refreshed. No cloud APIs were called.")
      }
      onScan={() => {
        if (!canAct) return;
        log(
          "Demo scan requested",
          `${tenant.name} / ${scope}`,
          `Snapshot ${model.snapshot}`,
          "Demo action recorded; evidence unchanged",
        );
        setMessage(
          "Demo scan recorded in the audit log. Evidence and snapshot time are unchanged.",
        );
      }}
    />
  );
}

export function Dashboard() {
  const { tenant, scope } = useProduct();
  const { region } = useAccountScope();
  return <DemoAccountDashboard key={`${tenant.id}:${scope}:${region}`} />;
}
