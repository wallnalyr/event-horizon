import { useState, useEffect, useRef, useCallback } from 'react'

export function LineNumberedTextarea({
  value,
  onChange,
  className = '',
  minRows = 5,
  disabled = false,
  id,
  placeholder = ''
}) {
  const textareaRef = useRef(null)
  const canvasRef = useRef(null)
  const contextRef = useRef(null)
  const recalcTimeoutRef = useRef(null)

  const [lineData, setLineData] = useState([{ lineNumber: 1, isOdd: true }])
  const [textareaHeight, setTextareaHeight] = useState(0)

  const lineHeight = 1.8
  const fontSize = 12 // text-xs is 12px
  const lineHeightPx = lineHeight * fontSize
  const paddingY = 16 // py-4 = 16px

  // Get or create canvas context for text measurement
  const getContext = useCallback(() => {
    if (!canvasRef.current) {
      canvasRef.current = document.createElement('canvas')
      contextRef.current = canvasRef.current.getContext('2d')
    }
    return contextRef.current
  }, [])

  // Measure text width using canvas
  const measureText = useCallback((text) => {
    const ctx = getContext()
    if (!ctx) return 0
    return ctx.measureText(text).width
  }, [getContext])

  // Sync canvas font with textarea styles
  const syncFont = useCallback(() => {
    const textarea = textareaRef.current
    const ctx = getContext()
    if (!textarea || !ctx) return

    const styles = window.getComputedStyle(textarea)
    ctx.font = `${styles.fontSize} ${styles.fontFamily}`
  }, [getContext])

  // Calculate line numbers accounting for word wrap
  const calculateLineNumbers = useCallback((
    text,
    textareaWidth,
    paddingLeft,
    paddingRight
  ) => {
    const availableWidth = textareaWidth - paddingLeft - paddingRight
    if (availableWidth <= 0) {
      return [{ lineNumber: 1, isOdd: true }]
    }

    const logicalLines = text.split('\n')
    const result = []

    logicalLines.forEach((line, logicalIndex) => {
      const lineNumber = logicalIndex + 1
      const isOdd = lineNumber % 2 === 1

      if (line.trim() === '') {
        // Empty line takes 1 visual line
        result.push({ lineNumber, isOdd })
        return
      }

      // Calculate word wrap
      const words = line.split(' ')
      let visualLineCount = 0
      let currentLineText = ''

      words.forEach((word, wordIndex) => {
        const wordWithSpace = wordIndex === 0 ? word : ' ' + word
        const currentWidth = measureText(currentLineText)
        const wordWidth = measureText(wordWithSpace)

        if (currentWidth + wordWidth > availableWidth && currentLineText !== '') {
          visualLineCount++
          currentLineText = word
        } else {
          currentLineText += wordWithSpace
        }
      })

      // Count final line
      if (currentLineText !== '' || words.length === 0) {
        visualLineCount++
      }

      // Ensure at least 1 visual line
      visualLineCount = Math.max(1, visualLineCount)

      // First visual line gets the line number, rest are blank
      for (let i = 0; i < visualLineCount; i++) {
        result.push({
          lineNumber: i === 0 ? lineNumber : '',
          isOdd
        })
      }
    })

    return result.length > 0 ? result : [{ lineNumber: 1, isOdd: true }]
  }, [measureText])

  // Recalculate line numbers (debounced)
  const recalculateLines = useCallback(() => {
    if (recalcTimeoutRef.current) {
      window.clearTimeout(recalcTimeoutRef.current)
    }

    recalcTimeoutRef.current = window.setTimeout(() => {
      const textarea = textareaRef.current
      if (!textarea) return

      syncFont()
      const styles = window.getComputedStyle(textarea)
      const width = textarea.getBoundingClientRect().width
      const paddingLeft = parseFloat(styles.paddingLeft) || 0
      const paddingRight = parseFloat(styles.paddingRight) || 0

      const newLineData = calculateLineNumbers(value, width, paddingLeft, paddingRight)
      setLineData(newLineData)
    }, 10)
  }, [value, syncFont, calculateLineNumbers])

  // Recalculate on value change or mount
  useEffect(() => {
    recalculateLines()
  }, [recalculateLines])

  // Auto-resize textarea based on content
  useEffect(() => {
    const textarea = textareaRef.current
    if (!textarea) return

    // Reset height to auto to get accurate scrollHeight
    textarea.style.height = 'auto'
    const scrollHeight = textarea.scrollHeight
    const minHeight = minRows * lineHeightPx + paddingY * 2
    const newHeight = Math.max(scrollHeight, minHeight)
    textarea.style.height = `${newHeight}px`
    setTextareaHeight(newHeight)
  }, [value, minRows, lineHeightPx, paddingY])

  // ResizeObserver for width changes
  useEffect(() => {
    const textarea = textareaRef.current
    if (!textarea) return

    const resizeObserver = new ResizeObserver(() => {
      recalculateLines()
    })

    resizeObserver.observe(textarea)
    return () => {
      resizeObserver.disconnect()
      if (recalcTimeoutRef.current) {
        window.clearTimeout(recalcTimeoutRef.current)
      }
    }
  }, [recalculateLines])

  // Calculate minimum height based on minRows
  const minHeight = minRows * lineHeightPx + paddingY * 2

  return (
    <div className={`kurz-line-textarea ${className}`}>
      {/* Line Numbers Gutter */}
      <div
        className="line-number-gutter"
        style={{ minHeight, height: textareaHeight || minHeight }}
      >
        {lineData.map((data, index) => (
          <div
            key={index}
            className={data.isOdd ? 'bg-kurz-bg' : 'bg-white'}
            style={{ height: `${lineHeightPx}px`, lineHeight: `${lineHeightPx}px` }}
          >
            {data.lineNumber || '\u00A0'}
          </div>
        ))}
        {/* Pad with empty lines if needed */}
        {lineData.length < minRows && Array.from({ length: minRows - lineData.length }).map((_, i) => {
          // Continue alternating from where lineData left off
          const lastIsOdd = lineData.length > 0 ? lineData[lineData.length - 1].isOdd : true
          const lastLineNum = lineData.length > 0 ? (lineData[lineData.length - 1].lineNumber || lineData.filter(d => d.lineNumber).pop()?.lineNumber || 0) : 0
          const nextLineNum = typeof lastLineNum === 'number' ? lastLineNum + i + 1 : i + 1
          const isOdd = nextLineNum % 2 === 1
          return (
            <div
              key={`pad-${i}`}
              className={isOdd ? 'bg-kurz-bg' : 'bg-white'}
              style={{ height: `${lineHeightPx}px`, lineHeight: `${lineHeightPx}px` }}
            >
              &nbsp;
            </div>
          )
        })}
      </div>

      {/* Textarea Wrapper */}
      <div className="relative flex-1 min-w-0" style={{ minHeight, height: textareaHeight || minHeight }}>
        {/* Background Stripes */}
        <div className="absolute inset-0 pointer-events-none py-4">
          {lineData.map((data, index) => (
            <div
              key={index}
              className={data.isOdd ? 'bg-kurz-bg' : 'bg-white'}
              style={{ height: `${lineHeightPx}px` }}
            />
          ))}
          {/* Pad with empty lines if needed */}
          {lineData.length < minRows && Array.from({ length: minRows - lineData.length }).map((_, i) => {
            const lastLineNum = lineData.length > 0 ? (lineData[lineData.length - 1].lineNumber || lineData.filter(d => d.lineNumber).pop()?.lineNumber || 0) : 0
            const nextLineNum = typeof lastLineNum === 'number' ? lastLineNum + i + 1 : i + 1
            const isOdd = nextLineNum % 2 === 1
            return (
              <div
                key={`pad-${i}`}
                className={isOdd ? 'bg-kurz-bg' : 'bg-white'}
                style={{ height: `${lineHeightPx}px` }}
              />
            )
          })}
        </div>

        {/* Textarea */}
        <textarea
          ref={textareaRef}
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          placeholder={placeholder}
          spellCheck={false}
          className="relative w-full bg-transparent border-none outline-none px-3 py-4 font-mono text-xs text-kurz-dark resize-none"
          style={{
            lineHeight: `${lineHeightPx}px`,
            minHeight,
            overflow: 'hidden',
          }}
          aria-label="Shared clipboard content"
        />
      </div>
    </div>
  )
}
