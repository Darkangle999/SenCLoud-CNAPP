import {
  AlertTriangle, Boxes, Cloud, Container, Database, FileText, Globe,
  HardDrive, KeyRound, Network, Server, Shield, ShieldCheck, UserRound,
  Users, Zap,
} from 'lucide-react'
import AppLoadBalancer from 'react-aws-icons/dist/aws/compute/AppLoadBalancer'
import ECR from 'react-aws-icons/dist/aws/compute/ECR'
import InternetGateway from 'react-aws-icons/dist/aws/compute/InternetGateway'
import NATGateway from 'react-aws-icons/dist/aws/compute/NATGateway'
import RouteTable from 'react-aws-icons/dist/aws/compute/RouteTable'
import VPCSubnet from 'react-aws-icons/dist/aws/compute/VPCSubnet'
import IAMUser from 'react-aws-icons/dist/aws/general/User'
import APIGateway from 'react-aws-icons/dist/aws/logo/APIGateway'
import CloudFront from 'react-aws-icons/dist/aws/logo/CloudFront'
import CloudTrail from 'react-aws-icons/dist/aws/logo/CloudTrail'
import CloudWatch from 'react-aws-icons/dist/aws/logo/CloudWatch'
import Config from 'react-aws-icons/dist/aws/logo/Config'
import DynamoDB from 'react-aws-icons/dist/aws/logo/DynamoDB'
import EC2 from 'react-aws-icons/dist/aws/logo/EC2'
import ECS from 'react-aws-icons/dist/aws/logo/ECS'
import EFS from 'react-aws-icons/dist/aws/logo/EFS'
import IAM from 'react-aws-icons/dist/aws/logo/IAM'
import KMS from 'react-aws-icons/dist/aws/logo/KMS'
import Lambda from 'react-aws-icons/dist/aws/logo/Lambda'
import RDS from 'react-aws-icons/dist/aws/logo/RDS'
import Route53 from 'react-aws-icons/dist/aws/logo/Route53'
import S3 from 'react-aws-icons/dist/aws/logo/S3'
import SNS from 'react-aws-icons/dist/aws/logo/SNS'
import SQS from 'react-aws-icons/dist/aws/logo/SQS'
import WAF from 'react-aws-icons/dist/aws/logo/WAF'
import VPC from 'react-aws-icons/dist/aws/logo/VPC'
import Role from 'react-aws-icons/dist/aws/security/Role'
import EBS from 'react-aws-icons/dist/aws/storage/EBS'
import Snapshot from 'react-aws-icons/dist/aws/storage/Snapshot'
import type { GraphKind, GraphNode } from '../types'

type IconNode = Pick<GraphNode, 'kind' | 'asset_type' | 'properties'>
type ResourceGlyph = typeof EC2 | typeof Shield
type IconChoice = { Icon: ResourceGlyph; label: string; key: string }
const normalize = (value: string) => value.toLowerCase().replace(/[./:_-]+/g, ' ').replace(/\s+/g, ' ').trim()
const matches = (value: string, pattern: string) => new RegExp(`(?:^| )(?:${pattern})(?: |$)`).test(value)

function genericIcon(value: string): ResourceGlyph {
  if (matches(value, 'security group|firewall|shield|guardduty')) return Shield
  if (matches(value, 'role|identity|iam|service account|principal')) return KeyRound
  if (matches(value, 'user|users|group')) return UserRound
  if (matches(value, 'bucket|storage|s3|blob|ebs|disk|snapshot|volume')) return HardDrive
  if (matches(value, 'database|sql|rds|dynamodb|cosmos')) return Database
  if (matches(value, 'eks|kubernetes|cluster')) return Boxes
  if (matches(value, 'ecs|container|registry|ecr')) return Container
  if (matches(value, 'lambda|function|functions')) return Zap
  if (matches(value, 'vpc|network|subnet|gateway|balancer|route')) return Network
  if (matches(value, 'trail|log|cloudtrail|cloudwatch')) return FileText
  if (matches(value, 'compute|ec2|instance|virtual machine|vm')) return Server
  return Cloud
}

function resourceIcon(service: string, type: string): IconChoice {
  const value = normalize(`${service} ${type}`)
  const pick = (Icon: ResourceGlyph, label: string, key: string): IconChoice => {
    const legacyDefault = (Icon as ResourceGlyph & { default?: ResourceGlyph }).default
    return { Icon: legacyDefault ?? Icon, label, key }
  }
  if (matches(value, 'azure|microsoft|gcp|google|gce|gcs')) {
    return pick(genericIcon(value), type || service, 'cloud-resource')
  }
  if (matches(value, 'security group|securitygroup')) return pick(Shield, 'Security group', 'security-group')
  if (matches(value, 'internet gateway|internetgateway|igw')) return pick(InternetGateway, 'Internet gateway', 'internet-gateway')
  if (matches(value, 'nat gateway|natgateway')) return pick(NATGateway, 'NAT gateway', 'nat-gateway')
  if (matches(value, 'route table|routetable')) return pick(RouteTable, 'Route table', 'route-table')
  if (matches(value, 'subnet')) return pick(VPCSubnet, 'VPC subnet', 'subnet')
  if (matches(value, 'snapshot')) return pick(Snapshot, 'EBS snapshot', 'ebs-snapshot')
  if (matches(value, 'ebs|volume')) return pick(EBS, 'Amazon EBS', 'ebs')
  if (matches(value, 'eks|kubernetes')) return pick(Boxes, 'Amazon EKS', 'eks')
  if (matches(value, 'ecr|registry')) return pick(ECR, 'Amazon ECR', 'ecr')
  if (matches(value, 'ecs|fargate')) return pick(ECS, 'Amazon ECS', 'ecs')
  if (matches(value, 'lambda')) return pick(Lambda, 'AWS Lambda', 'lambda')
  if (matches(value, 's3|bucket')) return pick(S3, 'Amazon S3', 's3')
  if (matches(value, 'dynamodb')) return pick(DynamoDB, 'Amazon DynamoDB', 'dynamodb')
  if (matches(value, 'rds|aurora')) return pick(RDS, 'Amazon RDS', 'rds')
  if (matches(value, 'efs')) return pick(EFS, 'Amazon EFS', 'efs')
  if (matches(value, 'load balancer|loadbalancer|elb|alb|nlb|elbv2')) return pick(AppLoadBalancer, 'Elastic Load Balancing', 'elb')
  if (matches(value, 'cloudtrail')) return pick(CloudTrail, 'AWS CloudTrail', 'cloudtrail')
  if (matches(value, 'cloudwatch')) return pick(CloudWatch, 'Amazon CloudWatch', 'cloudwatch')
  if (matches(value, 'guardduty')) return pick(ShieldCheck, 'Amazon GuardDuty', 'guardduty')
  if (matches(value, 'waf|wafv2')) return pick(WAF, 'AWS WAF', 'waf')
  if (matches(value, 'kms')) return pick(KMS, 'AWS KMS', 'kms')
  if (matches(value, 'role')) return pick(Role, 'IAM role', 'iam-role')
  if (matches(value, 'iam') && matches(value, 'user')) return pick(IAMUser, 'IAM user', 'iam-user')
  if (matches(value, 'iam')) return pick(IAM, 'AWS IAM', 'iam')
  if (matches(value, 'cloudfront')) return pick(CloudFront, 'Amazon CloudFront', 'cloudfront')
  if (matches(value, 'route53|route 53')) return pick(Route53, 'Amazon Route 53', 'route53')
  if (matches(value, 'apigateway|api gateway')) return pick(APIGateway, 'Amazon API Gateway', 'api-gateway')
  if (matches(value, 'sqs')) return pick(SQS, 'Amazon SQS', 'sqs')
  if (matches(value, 'sns')) return pick(SNS, 'Amazon SNS', 'sns')
  if (matches(value, 'config')) return pick(Config, 'AWS Config', 'config')
  if (matches(value, 'vpc')) return pick(VPC, 'Amazon VPC', 'vpc')
  if (matches(value, 'ec2')) return pick(EC2, 'Amazon EC2', 'ec2')
  return pick(genericIcon(value), type || service || 'Cloud resource', 'cloud-resource')
}

export function CloudResourceIcon({ service, type = '', size = 24, color }: {
  service: string
  type?: string
  size?: number
  color?: string
}) {
  const { Icon, label, key } = resourceIcon(service, type)
  return <span role="img" aria-label={label} data-resource-icon={key} style={{ display: 'inline-flex', width: size, height: size, flexShrink: 0, verticalAlign: 'middle', color }}><Icon size={size} color={color} /></span>
}

const kindServices: Record<GraphKind, string> = {
  internet: 'Internet', external: 'External identity', user: 'IAM user',
  compute: 'EC2', security_group: 'Security group', role: 'IAM role',
  bucket: 'S3', database: 'RDS', finding: 'Finding',
}

export function NodeIcon({ node, size = 26, color }: {
  node: IconNode | { kind: GraphKind }
  size?: number
  color?: string
}) {
  const n = node as IconNode
  const Generic = n.kind === 'finding' ? AlertTriangle : n.kind === 'internet' ? Globe : n.kind === 'external' ? Users : null
  if (Generic) return <Generic size={size} color={n.kind === 'finding' ? color || 'currentColor' : color} role="img" aria-label={kindServices[n.kind]} />
  const provider = String(n.properties?.provider ?? n.properties?.cloud_provider ?? '')
  const type = n.asset_type || kindServices[n.kind]
  return <CloudResourceIcon service={provider} type={type} size={size} color={color} />
}
