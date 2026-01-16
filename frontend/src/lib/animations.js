// Animation variants for framer-motion

// File list item animations
export const fileItemVariants = {
  hidden: {
    opacity: 0,
    x: -20,
    scale: 0.95
  },
  visible: {
    opacity: 1,
    x: 0,
    scale: 1,
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 24
    }
  },
  exit: {
    opacity: 0,
    x: 100,
    scale: 0.8,
    transition: {
      duration: 0.3
    }
  }
}

// Shred animation (paper shredder effect)
export const shredVariants = {
  initial: {
    scaleY: 1,
    opacity: 1,
    filter: 'blur(0px)'
  },
  shredding: {
    scaleY: 0,
    opacity: 0,
    filter: 'blur(4px)',
    transition: {
      duration: 0.4,
      ease: 'easeIn'
    }
  }
}

// Upload zone drag states
export const uploadZoneVariants = {
  idle: {
    scale: 1,
    borderColor: '#1a1a2e'
  },
  dragging: {
    scale: 1.02,
    borderColor: '#00d4ff',
    transition: {
      type: 'spring',
      stiffness: 400,
      damping: 25
    }
  }
}

// Modal animations
export const modalOverlayVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { duration: 0.2 }
  },
  exit: {
    opacity: 0,
    transition: { duration: 0.15 }
  }
}

export const modalContentVariants = {
  hidden: {
    opacity: 0,
    scale: 0.9,
    y: 20
  },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: 'spring',
      stiffness: 300,
      damping: 25
    }
  },
  exit: {
    opacity: 0,
    scale: 0.9,
    y: 20,
    transition: { duration: 0.15 }
  }
}

// Container animations for staggered children
export const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.1
    }
  }
}

// Skeleton pulse animation
export const skeletonVariants = {
  pulse: {
    opacity: [0.4, 0.7, 0.4],
    transition: {
      duration: 1.5,
      repeat: Infinity,
      ease: 'easeInOut'
    }
  }
}
