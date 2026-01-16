import { motion } from 'framer-motion'
import { skeletonVariants } from '../../lib/animations'

export function Skeleton({ className = '' }) {
  return (
    <motion.div
      className={`bg-gray-200 rounded ${className}`}
      variants={skeletonVariants}
      animate="pulse"
    />
  )
}

export function FileCardSkeleton() {
  return (
    <div className="p-4 flex items-center gap-3">
      <Skeleton className="w-10 h-10 rounded" />
      <div className="flex-1 space-y-2">
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-3 w-1/2" />
      </div>
      <div className="flex gap-2">
        <Skeleton className="w-11 h-11 rounded" />
        <Skeleton className="w-11 h-11 rounded" />
      </div>
    </div>
  )
}
