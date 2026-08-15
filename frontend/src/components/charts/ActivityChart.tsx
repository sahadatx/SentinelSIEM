const points = [34, 48, 42, 64, 58, 77, 71, 88, 69, 94, 82, 108, 96, 112, 103, 126, 118, 135, 121, 144, 138, 151, 145, 160];

export function ActivityChart() {
  const max = Math.max(...points);
  const path = points.map((value, index) => {
    const x = (index / (points.length - 1)) * 100;
    const y = 100 - (value / max) * 82;
    return `${x},${y}`;
  }).join(" ");
  return (
    <div className="chart-wrap">
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label="Event activity trend">
        <defs><linearGradient id="activity-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopOpacity=".28" /><stop offset="100%" stopOpacity="0" /></linearGradient></defs>
        <polygon points={`0,100 ${path} 100,100`} fill="url(#activity-fill)" />
        <polyline points={path} fill="none" stroke="currentColor" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="chart-axis"><span>24h ago</span><span>12h</span><span>Now</span></div>
    </div>
  );
}
