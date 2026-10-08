import { motion } from 'motion/react'
import { useEffect, useState } from 'react'

export function ProgressBar({ isScanning }: { isScanning: boolean }) {
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>
    if (isScanning) {
      setProgress(0)
      // Simulate progress going up to 90% while waiting for the backend
      interval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) return prev
          return prev + Math.random() * 5
        })
      }, 500)
    } else {
      // When scan finishes (isScanning becomes false), jump to 100%
      setProgress(100)
    }
    return () => clearInterval(interval)
  }, [isScanning])

  if (!isScanning && progress === 100) {
    // Hide the bar after it hits 100% (fade out effect could be handled by motion)
    setTimeout(() => setProgress(0), 1000)
  }

  if (progress === 0 && !isScanning) return null

  return (
    <div style={{ marginTop: 12, marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: 4, color: 'var(--text-dim)' }}>
        <span>Scanning AWS resources & running rules...</span>
        <span>{Math.round(progress)}%</span>
      </div>
      <div style={{
        width: '100%',
        height: '4px',
        backgroundColor: 'var(--b3)',
        borderRadius: '2px',
        overflow: 'hidden'
      }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ ease: 'easeInOut', duration: 0.5 }}
          style={{
            height: '100%',
            backgroundColor: 'var(--brand)',
            borderRadius: '2px'
          }}
        />
      </div>
    </div>
  )
}
