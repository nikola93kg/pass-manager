// ============================================================
// LoadingScreen — shown while checking vault state
// ============================================================

export default function LoadingScreen() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950">
      <div className="flex flex-col items-center gap-4">
        <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-gray-400 text-sm">Loading vault...</p>
      </div>
    </div>
  );
}
