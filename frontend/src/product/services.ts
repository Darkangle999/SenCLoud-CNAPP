import type { Asset, SecurityService } from "./data";

export type CnappService = "CNAPP" | SecurityService;

export const securityServices: SecurityService[] = [
  "CSPM",
  "DSPM",
  "CIEM",
  "CWPP",
];

const commonPaths = [
  "/",
  "/accounts",
  "/inventory",
  "/findings",
  "/reports",
  "/integrations",
  "/audit-logs",
  "/settings",
];

const servicePaths: Record<Exclude<CnappService, "CNAPP">, string[]> = {
  CSPM: [
    ...commonPaths,
    "/cloud-configuration",
    "/code-security",
    "/iac",
    "/compliance",
    "/policies",
    "/exceptions",
    "/remediation",
    "/geography",
  ],
  DSPM: [...commonPaths, "/data"],
  CIEM: [...commonPaths, "/identities", "/identity"],
  CWPP: [
    ...commonPaths,
    "/vulnerabilities",
    "/kubernetes",
    "/workloads",
    "/threats",
    "/cve-database",
    "/ebpf",
  ],
};

const combinedPaths = ["/security-graph", "/architecture", "/attack-paths"];

function routeRoot(pathname: string) {
  const first = pathname.split("/").filter(Boolean)[0];
  return first ? `/${first}` : "/";
}

export function serviceAllowsPath(
  service: CnappService,
  pathname: string,
  subscribedServices: SecurityService[] = securityServices,
) {
  const root = routeRoot(pathname);
  if (service === "CNAPP") {
    return (
      (subscribedServices.length > 1 && combinedPaths.includes(root)) ||
      subscribedServices.some((item) => servicePaths[item].includes(root))
    );
  }
  return (
    subscribedServices.includes(service) && servicePaths[service].includes(root)
  );
}

function domainAllowsAsset(service: SecurityService, asset: Asset) {
  if (service === "CSPM") return true;
  if (service === "DSPM") return asset.category === "Data";
  if (service === "CIEM") return asset.category === "Identity";
  return asset.category === "Compute";
}

export function serviceAllowsAsset(
  service: CnappService,
  asset: Asset,
  subscribedServices: SecurityService[] = securityServices,
) {
  if (service === "CNAPP") {
    return subscribedServices.some((item) => domainAllowsAsset(item, asset));
  }
  return (
    subscribedServices.includes(service) && domainAllowsAsset(service, asset)
  );
}
