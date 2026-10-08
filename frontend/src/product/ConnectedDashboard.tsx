import { useAccountScope } from "../lib/accountScope";
import { CnappOverview } from "./CnappOverview";
import { useConnectedDashboardModel } from "./useConnectedDashboardModel";

function ConnectedAccountDashboard() {
  const dashboard = useConnectedDashboardModel();
  return <CnappOverview {...dashboard} />;
}

export function ConnectedDashboard() {
  const { accountId, provider, region } = useAccountScope();
  // A new scope starts with no evidence. In-flight requests and retained hook
  // values from the previous account cannot appear in the next workspace.
  return (
    <ConnectedAccountDashboard
      key={`${provider}:${accountId ?? "unselected"}:${region}`}
    />
  );
}
