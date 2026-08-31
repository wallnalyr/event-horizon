import {
  Xmark,
  Copy,
  ClipboardCheck,
  Trash,
  Download,
  MediaImage,
  Lock,
  LockSlash,
  DataTransferBoth,
  WarningTriangle,
  NavArrowUp,
  NavArrowDown,
  HelpCircle,
  Settings,
  CloudUpload,
  MediaVideo,
  MusicNote,
  Page,
  Archive,
  Table2Columns,
  Presentation,
  Text as TextIcon,
  Code,
  EmptyPage,
  PlanetAlt,
  Box,
  FolderMinus,
  MediaImagePlus
} from 'iconoir-react'

// Maps the app's semantic icon names (previously Material Symbols) to Iconoir
// components. Iconoir icons stroke with currentColor and are rendered at 1em, so
// existing Tailwind color (`text-kurz-*`) and size (`text-lg`, `text-3xl`, …)
// classes continue to control color and size exactly as before.
const ICONS = {
  // UI
  close: Xmark,
  content_copy: Copy,
  content_paste: ClipboardCheck,
  delete_forever: Trash,
  download: Download,
  image: MediaImage,
  add_photo_alternate: MediaImagePlus,
  lock: Lock,
  lock_open: LockSlash,
  swap_horiz: DataTransferBoth,
  warning: WarningTriangle,
  expand_less: NavArrowUp,
  expand_more: NavArrowDown,
  help: HelpCircle,
  admin_panel_settings: Settings,
  cloud_upload: CloudUpload,
  cyclone: PlanetAlt,
  inventory_2: Box,
  folder_off: FolderMinus,
  // File-type icons
  movie: MediaVideo,
  audio_file: MusicNote,
  picture_as_pdf: Page,
  folder_zip: Archive,
  description: Page,
  table_chart: Table2Columns,
  slideshow: Presentation,
  article: TextIcon,
  data_object: Code,
  code: Code,
  draft: EmptyPage
}

// Loading states render a clean single-arc spinner. The caller supplies the spin
// animation (Tailwind `animate-spin` or a Framer Motion rotate) as before.
const SPINNER_NAMES = new Set(['progress_activity', 'hourglass_empty', 'spinner'])

function Spinner({ className }) {
  return (
    <svg
      width="1em"
      height="1em"
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2.2" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinecap="round"
      />
    </svg>
  )
}

/**
 * Icon renders an Iconoir glyph by its semantic name. Unknown names fall back to
 * a blank page so a missing mapping never crashes the UI.
 */
export function Icon({ name, className = '', strokeWidth = 1.8, ...rest }) {
  if (SPINNER_NAMES.has(name)) {
    return <Spinner className={className} {...rest} />
  }
  const Glyph = ICONS[name] || EmptyPage
  return (
    <Glyph
      width="1em"
      height="1em"
      strokeWidth={strokeWidth}
      className={className}
      aria-hidden="true"
      {...rest}
    />
  )
}
