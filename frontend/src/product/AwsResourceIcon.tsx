import { CloudResourceIcon } from "../lib/awsIcons";

export function AwsResourceIcon({
  service,
  type,
  size = 18,
}: {
  service: string;
  type?: string;
  size?: number;
}) {
  return <CloudResourceIcon service={service} type={type} size={size} />;
}
