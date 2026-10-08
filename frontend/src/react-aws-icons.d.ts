// react-aws-icons ships untyped CJS modules; each deep path is a single default
// export rendering an inline SVG and accepting a numeric `size`.
declare module 'react-aws-icons/dist/aws/*' {
  import type { ComponentType } from 'react'
  const Icon: ComponentType<{ size?: number } & Record<string, unknown>>
  export default Icon
}
