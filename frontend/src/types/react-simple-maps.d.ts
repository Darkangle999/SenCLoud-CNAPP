// Minimal ambient declarations for react-simple-maps v3 (ships no bundled
// types). Only the pieces the Geography page uses are declared. NOTE: no
// top-level imports here — this must stay a global script file so the
// `declare module` block is an ambient declaration, not an augmentation.

declare module 'react-simple-maps' {
  import type { CSSProperties, ReactNode, MouseEvent } from 'react'

  export interface RSMGeography {
    rKey: string
    id?: string
    properties: Record<string, unknown>
  }

  export function ComposableMap(props: {
    width?: number
    height?: number
    projection?: string
    projectionConfig?: { scale?: number; center?: [number, number]; rotate?: [number, number, number] }
    style?: CSSProperties
    className?: string
    children?: ReactNode
  }): JSX.Element

  export function Geographies(props: {
    geography: string | object
    children: (props: { geographies: RSMGeography[] }) => ReactNode
  }): JSX.Element

  export function Geography(props: {
    geography: RSMGeography
    fill?: string
    stroke?: string
    strokeWidth?: number
    onMouseEnter?: (e: MouseEvent<SVGPathElement>) => void
    onMouseLeave?: (e: MouseEvent<SVGPathElement>) => void
  }): JSX.Element

  export function Marker(props: {
    coordinates: [number, number]
    children?: ReactNode
    onMouseEnter?: (e: MouseEvent<SVGGElement>) => void
    onMouseLeave?: (e: MouseEvent<SVGGElement>) => void
  }): JSX.Element
}


