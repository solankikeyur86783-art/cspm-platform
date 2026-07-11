import { useState, useEffect, useRef } from 'react';

/* ─── Shared Types ──────────────────────────────────────────────────────── */
interface DataPoint {
  label: string;
  value: number;
  color?: string;
}

/* ─── Area Chart ────────────────────────────────────────────────────────── */
interface AreaChartProps {
  data: DataPoint[];
  data2?: DataPoint[];
  height?: number;
  color?: string;
  color2?: string;
  showGrid?: boolean;
  showLabels?: boolean;
  animated?: boolean;
}

export const AreaChart = ({
  data,
  data2,
  height = 256,
  color = '#aac7ff',
  color2 = '#4edea3',
  showGrid = true,
  showLabels = true,
  animated = true,
}: AreaChartProps) => {
  const [mounted, setMounted] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; value: number; label: string } | null>(null);

  useEffect(() => {
    if (animated) {
      const t = setTimeout(() => setMounted(true), 100);
      return () => clearTimeout(t);
    }
    setMounted(true);
  }, [animated]);

  if (data.length === 0) return null;

  const w = 1000;
  const h = height;
  const padX = 0;
  const padY = 10;
  const maxVal = Math.max(...data.map((d) => d.value), ...(data2 || []).map((d) => d.value)) * 1.1;

  const toX = (i: number) => padX + (i / (data.length - 1)) * (w - padX * 2);
  const toY = (v: number) => padY + (1 - v / maxVal) * (h - padY * 2);

  const buildPath = (pts: DataPoint[]) => pts.map((d, i) => `${i === 0 ? 'M' : 'L'}${toX(i)},${toY(d.value)}`).join(' ');
  const buildArea = (pts: DataPoint[]) => {
    const line = buildPath(pts);
    return `${line} L${toX(pts.length - 1)},${h} L${toX(0)},${h} Z`;
  };

  const gradId1 = 'area-grad-1';
  const gradId2 = 'area-grad-2';

  return (
    <div className="relative w-full" style={{ height }}>
      <svg
        ref={svgRef}
        className="w-full h-full overflow-visible"
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        onMouseLeave={() => setTooltip(null)}
      >
        <defs>
          <linearGradient id={gradId1} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.3" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
          <linearGradient id={gradId2} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={color2} stopOpacity="0.2" />
            <stop offset="100%" stopColor={color2} stopOpacity="0" />
          </linearGradient>
        </defs>
        {showGrid &&
          [0, 25, 50, 75, 100].map((pct) => (
            <line
              key={pct}
              x1="0"
              x2={w}
              y1={toY((pct / 100) * maxVal)}
              y2={toY((pct / 100) * maxVal)}
              stroke="#414754"
              strokeOpacity="0.3"
              strokeDasharray="4 4"
            />
          ))}
        {/* Area fills */}
        <path
          d={buildArea(data)}
          fill={`url(#${gradId1})`}
          className={animated ? 'chart-fade-in' : ''}
          style={{ opacity: mounted ? 1 : 0, transition: 'opacity 1s ease-out' }}
        />
        {data2 && (
          <path
            d={buildArea(data2)}
            fill={`url(#${gradId2})`}
            className={animated ? 'chart-fade-in' : ''}
            style={{ opacity: mounted ? 1 : 0, transition: 'opacity 1.2s ease-out' }}
          />
        )}
        {/* Lines */}
        <path
          d={buildPath(data)}
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          className={animated ? 'chart-line-draw' : ''}
          style={{ opacity: mounted ? 1 : 0, transition: 'opacity 0.6s ease-out' }}
        />
        {data2 && (
          <path
            d={buildPath(data2)}
            fill="none"
            stroke={color2}
            strokeWidth="2"
            strokeDasharray="5 5"
            style={{ opacity: mounted ? 1 : 0, transition: 'opacity 0.8s ease-out' }}
          />
        )}
        {/* Hover dots */}
        {data.map((d, i) => (
          <circle
            key={i}
            cx={toX(i)}
            cy={toY(d.value)}
            r="12"
            fill="transparent"
            className="cursor-pointer"
            onMouseEnter={() => {
              const rect = svgRef.current?.getBoundingClientRect();
              if (rect) {
                setTooltip({
                  x: (toX(i) / w) * rect.width,
                  y: (toY(d.value) / h) * rect.height,
                  value: d.value,
                  label: d.label,
                });
              }
            }}
          />
        ))}
        {tooltip && (
          <circle
            cx={(tooltip.x / (svgRef.current?.getBoundingClientRect()?.width || 1)) * w}
            cy={(tooltip.y / (svgRef.current?.getBoundingClientRect()?.height || 1)) * h}
            r="4"
            fill={color}
            className="animate-pulse"
          />
        )}
      </svg>
      {tooltip && (
        <div
          className="absolute pointer-events-none bg-surface-container-highest border border-outline-variant/30 rounded-lg px-3 py-2 shadow-xl z-10 text-xs"
          style={{ left: tooltip.x - 40, top: tooltip.y - 50 }}
        >
          <div className="text-on-surface-variant">{tooltip.label}</div>
          <div className="text-on-surface font-bold text-sm">{tooltip.value}</div>
        </div>
      )}
      {showLabels && data.length > 2 && (
        <div className="absolute bottom-[-24px] left-0 w-full flex justify-between font-mono text-[10px] text-on-surface-variant tracking-wider uppercase">
          <span>{data[0]?.label}</span>
          <span>{data[Math.floor(data.length / 2)]?.label}</span>
          <span>{data[data.length - 1]?.label}</span>
        </div>
      )}
    </div>
  );
};

/* ─── Donut Chart ───────────────────────────────────────────────────────── */
interface DonutChartProps {
  data: DataPoint[];
  size?: number;
  strokeWidth?: number;
  centerLabel?: string;
  centerValue?: string;
}

export const DonutChart = ({
  data,
  size = 160,
  strokeWidth = 14,
  centerLabel,
  centerValue,
}: DonutChartProps) => {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 200);
    return () => clearTimeout(t);
  }, []);

  const total = data.reduce((s, d) => s + d.value, 0);
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const center = size / 2;

  const defaultColors = ['#4edea3', '#aac7ff', '#ffb95f', '#ffb4ab', '#8b91a0'];
  let offset = 0;

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        <circle cx={center} cy={center} r={r} fill="transparent" stroke="#1c2026" strokeWidth={strokeWidth} />
        {data.map((d, i) => {
          const pct = total > 0 ? d.value / total : 0;
          const dashLen = pct * circumference;
          const currentOffset = offset;
          offset += dashLen;
          return (
            <circle
              key={i}
              cx={center}
              cy={center}
              r={r}
              fill="transparent"
              stroke={d.color || defaultColors[i % defaultColors.length]}
              strokeWidth={strokeWidth}
              strokeDasharray={`${mounted ? dashLen : 0} ${circumference}`}
              strokeDashoffset={-currentOffset}
              strokeLinecap="round"
              style={{ transition: 'stroke-dasharray 1s ease-out' }}
            />
          );
        })}
      </svg>
      {(centerLabel || centerValue) && (
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {centerValue && <span className="font-bold text-2xl text-on-surface">{centerValue}</span>}
          {centerLabel && <span className="text-[10px] text-on-surface-variant uppercase tracking-widest">{centerLabel}</span>}
        </div>
      )}
    </div>
  );
};

/* ─── Bar Chart ─────────────────────────────────────────────────────────── */
interface BarChartProps {
  data: DataPoint[];
  height?: number;
  showLabels?: boolean;
  showValues?: boolean;
}

export const BarChart = ({ data, height = 160, showLabels = true, showValues = true }: BarChartProps) => {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 200);
    return () => clearTimeout(t);
  }, []);

  const maxVal = Math.max(...data.map((d) => d.value));
  const defaultColors = ['#aac7ff', '#4edea3', '#ffb95f', '#ffb4ab', '#8b91a0'];

  return (
    <div className="w-full" style={{ height: height + 30 }}>
      <div className="flex items-end gap-3 h-full px-2" style={{ height }}>
        {data.map((d, i) => {
          const barH = maxVal > 0 ? (d.value / maxVal) * 100 : 0;
          const color = d.color || defaultColors[i % defaultColors.length];
          return (
            <div key={i} className="flex-1 flex flex-col items-center justify-end h-full group relative">
              {showValues && (
                <div
                  className="text-[10px] font-mono text-on-surface-variant mb-1 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  {d.value}
                </div>
              )}
              <div
                className="w-full rounded-t-md transition-all duration-700 ease-out relative overflow-hidden"
                style={{
                  height: mounted ? `${barH}%` : '0%',
                  backgroundColor: `${color}33`,
                }}
              >
                <div
                  className="absolute bottom-0 w-full rounded-t-md transition-all duration-1000 ease-out"
                  style={{
                    height: mounted ? '100%' : '0%',
                    backgroundColor: color,
                  }}
                />
              </div>
              {showLabels && (
                <div className="text-[10px] text-on-surface-variant uppercase tracking-wider mt-2 text-center truncate w-full">
                  {d.label}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* ─── Sparkline ─────────────────────────────────────────────────────────── */
interface SparklineProps {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
}

export const Sparkline = ({ data, color = '#4edea3', width = 80, height = 24 }: SparklineProps) => {
  if (data.length < 2) return null;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;

  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - ((v - min) / range) * (height - 4) - 2;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg width={width} height={height} className="overflow-visible">
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={data.length > 0 ? ((data.length - 1) / (data.length - 1)) * width : 0} cy={height - ((data[data.length - 1] - min) / range) * (height - 4) - 2} r="2" fill={color} />
    </svg>
  );
};
