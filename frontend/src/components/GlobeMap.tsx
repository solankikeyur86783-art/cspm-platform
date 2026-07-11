import { useEffect, useRef, useState } from 'react';

interface ThreatPoint {
  lat: number;
  lng: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  label: string;
  count: number;
}

interface AttackArc {
  from: { lat: number; lng: number };
  to: { lat: number; lng: number };
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface GlobeMapProps {
  threats?: ThreatPoint[];
  arcs?: AttackArc[];
  className?: string;
  autoRotate?: boolean;
  rotationSpeed?: number;
}

const DEFAULT_THREATS: ThreatPoint[] = [
  { lat: 37.7749, lng: -122.4194, severity: 'critical', label: 'US-WEST', count: 14 },
  { lat: 40.7128, lng: -74.006, severity: 'critical', label: 'US-EAST', count: 22 },
  { lat: 51.5074, lng: -0.1278, severity: 'high', label: 'EU-WEST', count: 8 },
  { lat: 52.52, lng: 13.405, severity: 'medium', label: 'EU-CENTRAL', count: 5 },
  { lat: 35.6762, lng: 139.6503, severity: 'high', label: 'AP-NORTHEAST', count: 11 },
  { lat: 1.3521, lng: 103.8198, severity: 'medium', label: 'AP-SOUTHEAST', count: 7 },
  { lat: -33.8688, lng: 151.2093, severity: 'low', label: 'AP-SOUTH', count: 3 },
  { lat: 28.6139, lng: 77.209, severity: 'high', label: 'SOUTH-ASIA', count: 9 },
  { lat: 55.7558, lng: 37.6173, severity: 'critical', label: 'EAST-EU', count: 18 },
  { lat: -23.5505, lng: -46.6333, severity: 'medium', label: 'SA-EAST', count: 4 },
];

const DEFAULT_ARCS: AttackArc[] = [
  { from: { lat: 55.7558, lng: 37.6173 }, to: { lat: 40.7128, lng: -74.006 }, severity: 'critical' },
  { from: { lat: 35.6762, lng: 139.6503 }, to: { lat: 37.7749, lng: -122.4194 }, severity: 'high' },
  { from: { lat: 28.6139, lng: 77.209 }, to: { lat: 51.5074, lng: -0.1278 }, severity: 'medium' },
  { from: { lat: 55.7558, lng: 37.6173 }, to: { lat: 52.52, lng: 13.405 }, severity: 'high' },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4444',
  high: '#ffb95f',
  medium: '#aac7ff',
  low: '#4edea3',
};

const GlobeMap = ({
  threats = DEFAULT_THREATS,
  arcs = DEFAULT_ARCS,
  className = '',
  autoRotate = true,
  rotationSpeed = 0.15,
}: GlobeMapProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const rotationRef = useRef(0);
  const [hoveredPoint, setHoveredPoint] = useState<ThreatPoint | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const isDragging = useRef(false);
  const lastMouse = useRef({ x: 0, y: 0 });
  const tiltRef = useRef(0.35);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resizeCanvas = () => {
      const rect = canvas.parentElement?.getBoundingClientRect();
      if (rect) {
        canvas.width = rect.width * window.devicePixelRatio;
        canvas.height = rect.height * window.devicePixelRatio;
        canvas.style.width = `${rect.width}px`;
        canvas.style.height = `${rect.height}px`;
        ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
      }
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const latLngTo3D = (lat: number, lng: number, radius: number) => {
      const phi = ((90 - lat) * Math.PI) / 180;
      const theta = ((lng + rotationRef.current) * Math.PI) / 180;
      const x = radius * Math.sin(phi) * Math.cos(theta);
      const y = radius * Math.cos(phi) * Math.cos(tiltRef.current) - radius * Math.sin(phi) * Math.sin(theta) * Math.sin(tiltRef.current);
      const z = radius * Math.sin(phi) * Math.sin(theta) * Math.cos(tiltRef.current) + radius * Math.cos(phi) * Math.sin(tiltRef.current);
      return { x, y, z };
    };

    const project = (p: { x: number; y: number; z: number }, cx: number, cy: number) => {
      return { x: cx + p.x, y: cy - p.y, z: p.z };
    };

    let time = 0;

    const render = () => {
      time += 0.016;
      const w = canvas.width / window.devicePixelRatio;
      const h = canvas.height / window.devicePixelRatio;
      const cx = w / 2;
      const cy = h / 2;
      const globeR = Math.min(w, h) * 0.38;

      ctx.clearRect(0, 0, w, h);

      // Stars
      ctx.save();
      for (let i = 0; i < 60; i++) {
        const sx = ((i * 137.5 + 50) % w);
        const sy = ((i * 97.3 + 30) % h);
        const brightness = 0.15 + 0.15 * Math.sin(time * 0.5 + i);
        ctx.fillStyle = `rgba(170, 199, 255, ${brightness})`;
        ctx.fillRect(sx, sy, 1, 1);
      }
      ctx.restore();

      // Globe glow
      const glow = ctx.createRadialGradient(cx, cy, globeR * 0.8, cx, cy, globeR * 1.4);
      glow.addColorStop(0, 'rgba(170, 199, 255, 0.06)');
      glow.addColorStop(1, 'rgba(170, 199, 255, 0)');
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, w, h);

      // Globe sphere
      const sphereGrad = ctx.createRadialGradient(cx - globeR * 0.2, cy - globeR * 0.2, 0, cx, cy, globeR);
      sphereGrad.addColorStop(0, 'rgba(30, 40, 55, 0.9)');
      sphereGrad.addColorStop(0.7, 'rgba(16, 20, 26, 0.95)');
      sphereGrad.addColorStop(1, 'rgba(10, 14, 20, 1)');
      ctx.beginPath();
      ctx.arc(cx, cy, globeR, 0, Math.PI * 2);
      ctx.fillStyle = sphereGrad;
      ctx.fill();
      ctx.strokeStyle = 'rgba(170, 199, 255, 0.15)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Latitude lines
      ctx.strokeStyle = 'rgba(170, 199, 255, 0.08)';
      ctx.lineWidth = 0.5;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lng = 0; lng <= 360; lng += 3) {
          const p3d = latLngTo3D(lat, lng, globeR);
          const p = project(p3d, cx, cy);
          if (p.z < 0) { first = true; continue; }
          if (first) { ctx.moveTo(p.x, p.y); first = false; }
          else ctx.lineTo(p.x, p.y);
        }
        ctx.stroke();
      }

      // Longitude lines
      for (let lng = 0; lng < 360; lng += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 3) {
          const p3d = latLngTo3D(lat, lng, globeR);
          const p = project(p3d, cx, cy);
          if (p.z < 0) { first = true; continue; }
          if (first) { ctx.moveTo(p.x, p.y); first = false; }
          else ctx.lineTo(p.x, p.y);
        }
        ctx.stroke();
      }

      // Simplified continent outlines (key coastline points)
      const continents: number[][][] = [
        // North America
        [[-10,70],[-25,60],[-50,48],[-75,45],[-80,30],[-95,30],[-105,20],[-115,33],[-125,48],[-140,60],[-165,65],[-170,72],[-140,72],[-80,72],[-60,75],[-10,70]],
        // South America
        [[-80,10],[-75,-5],[-70,-15],[-65,-25],[-57,-35],[-65,-50],[-73,-45],[-75,-30],[-80,-5],[-80,10]],
        // Europe
        [[-10,35],[0,40],[5,44],[15,45],[20,40],[25,40],[30,45],[40,42],[40,55],[30,60],[25,65],[10,63],[5,58],[-5,48],[-10,35]],
        // Africa
        [[-15,30],[0,35],[10,33],[20,32],[35,30],[42,12],[50,2],[40,-10],[35,-25],[28,-34],[18,-35],[12,-28],[8,-5],[5,5],[-5,5],[-15,10],[-18,15],[-15,30]],
        // Asia
        [[40,42],[50,40],[55,45],[65,40],[75,35],[80,28],[88,22],[95,15],[100,15],[105,22],[110,20],[120,22],[130,35],[135,35],[140,45],[142,53],[140,60],[130,55],[105,55],[80,55],[60,55],[40,55],[40,42]],
        // Australia
        [[115,-35],[120,-32],[135,-25],[145,-20],[150,-25],[153,-28],[150,-35],[140,-38],[130,-35],[115,-35]],
      ];

      ctx.strokeStyle = 'rgba(170, 199, 255, 0.2)';
      ctx.lineWidth = 0.8;
      continents.forEach(cont => {
        ctx.beginPath();
        let first = true;
        cont.forEach(([lng, lat]) => {
          const p3d = latLngTo3D(lat, lng, globeR * 1.001);
          const p = project(p3d, cx, cy);
          if (p.z < 0) { first = true; return; }
          if (first) { ctx.moveTo(p.x, p.y); first = false; }
          else ctx.lineTo(p.x, p.y);
        });
        ctx.stroke();
      });

      // Attack arcs
      arcs.forEach((arc) => {
        const fromP3d = latLngTo3D(arc.from.lat, arc.from.lng, globeR);
        const toP3d = latLngTo3D(arc.to.lat, arc.to.lng, globeR);
        const fromP = project(fromP3d, cx, cy);
        const toP = project(toP3d, cx, cy);

        if (fromP.z > 0 && toP.z > 0) {
          const midX = (fromP.x + toP.x) / 2;
          const midY = (fromP.y + toP.y) / 2;
          const dist = Math.sqrt((toP.x - fromP.x) ** 2 + (toP.y - fromP.y) ** 2);
          const arcHeight = dist * 0.35;
          const color = SEVERITY_COLORS[arc.severity] || '#aac7ff';

          ctx.save();
          ctx.strokeStyle = color;
          ctx.lineWidth = 1.5;
          ctx.globalAlpha = 0.4 + 0.3 * Math.sin(time * 2);
          ctx.setLineDash([4, 6]);
          ctx.beginPath();
          ctx.moveTo(fromP.x, fromP.y);
          ctx.quadraticCurveTo(midX, midY - arcHeight, toP.x, toP.y);
          ctx.stroke();
          ctx.setLineDash([]);

          // Animated dot along arc
          const t = (time * 0.5 + arcs.indexOf(arc) * 0.25) % 1;
          const dotX = (1 - t) * (1 - t) * fromP.x + 2 * (1 - t) * t * midX + t * t * toP.x;
          const dotY = (1 - t) * (1 - t) * fromP.y + 2 * (1 - t) * t * (midY - arcHeight) + t * t * toP.y;
          ctx.beginPath();
          ctx.arc(dotX, dotY, 2, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.globalAlpha = 0.8;
          ctx.fill();
          ctx.restore();
        }
      });

      // Threat hotspots
      threats.forEach((threat) => {
        const p3d = latLngTo3D(threat.lat, threat.lng, globeR * 1.005);
        const p = project(p3d, cx, cy);
        if (p.z <= 0) return;

        const color = SEVERITY_COLORS[threat.severity] || '#aac7ff';
        const pulseR = 3 + 2 * Math.sin(time * 3 + threat.lat);

        // Outer pulse
        ctx.save();
        ctx.beginPath();
        ctx.arc(p.x, p.y, pulseR + 6 + 4 * Math.sin(time * 2), 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.08 + 0.05 * Math.sin(time * 2);
        ctx.fill();

        // Inner pulse
        ctx.beginPath();
        ctx.arc(p.x, p.y, pulseR + 2, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.25;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.9;
        ctx.fill();

        // Glow
        ctx.shadowColor = color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.restore();
      });

      if (autoRotate && !isDragging.current) {
        rotationRef.current += rotationSpeed;
      }

      animRef.current = requestAnimationFrame(render);
    };

    animRef.current = requestAnimationFrame(render);

    // Mouse events
    const handleMouseDown = (e: MouseEvent) => {
      isDragging.current = true;
      lastMouse.current = { x: e.clientX, y: e.clientY };
    };
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      setMousePos({ x: e.clientX - rect.left, y: e.clientY - rect.top });

      if (isDragging.current) {
        const dx = e.clientX - lastMouse.current.x;
        const dy = e.clientY - lastMouse.current.y;
        rotationRef.current += dx * 0.3;
        tiltRef.current = Math.max(-1, Math.min(1, tiltRef.current + dy * 0.003));
        lastMouse.current = { x: e.clientX, y: e.clientY };
      }

      // Check hover over threat points
      const w2 = canvas.width / window.devicePixelRatio;
      const h2 = canvas.height / window.devicePixelRatio;
      const cx2 = w2 / 2;
      const cy2 = h2 / 2;
      const globeR2 = Math.min(w2, h2) * 0.38;

      let found: ThreatPoint | null = null;
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      threats.forEach((threat) => {
        const phi = ((90 - threat.lat) * Math.PI) / 180;
        const theta = ((threat.lng + rotationRef.current) * Math.PI) / 180;
        const x = globeR2 * Math.sin(phi) * Math.cos(theta);
        const y2 = globeR2 * Math.cos(phi) * Math.cos(tiltRef.current) - globeR2 * Math.sin(phi) * Math.sin(theta) * Math.sin(tiltRef.current);
        const z = globeR2 * Math.sin(phi) * Math.sin(theta) * Math.cos(tiltRef.current) + globeR2 * Math.cos(phi) * Math.sin(tiltRef.current);
        if (z <= 0) return;
        const px = cx2 + x;
        const py = cy2 - y2;
        const dist = Math.sqrt((mx - px) ** 2 + (my - py) ** 2);
        if (dist < 15) found = threat;
      });
      setHoveredPoint(found);
    };
    const handleMouseUp = () => { isDragging.current = false; };

    canvas.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener('resize', resizeCanvas);
      canvas.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [threats, arcs, autoRotate, rotationSpeed]);

  return (
    <div className={`relative w-full h-full ${className}`} style={{ minHeight: 200 }}>
      <canvas
        ref={canvasRef}
        className="w-full h-full cursor-grab active:cursor-grabbing"
      />
      {hoveredPoint && (
        <div
          className="absolute pointer-events-none bg-surface-container-highest/95 backdrop-blur-md border border-outline-variant/30 rounded-lg px-3 py-2 shadow-2xl z-10"
          style={{ left: mousePos.x + 12, top: mousePos.y - 10 }}
        >
          <div className="flex items-center gap-2 mb-1">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[hoveredPoint.severity] }}
            />
            <span className="text-xs font-bold text-on-surface uppercase tracking-wider">
              {hoveredPoint.label}
            </span>
          </div>
          <div className="text-[10px] text-on-surface-variant">
            {hoveredPoint.count} active threats •{' '}
            <span
              className="font-bold uppercase"
              style={{ color: SEVERITY_COLORS[hoveredPoint.severity] }}
            >
              {hoveredPoint.severity}
            </span>
          </div>
        </div>
      )}
      {/* Legend */}
      <div className="absolute bottom-2 left-2 flex gap-3">
        {['critical', 'high', 'medium', 'low'].map((sev) => (
          <div key={sev} className="flex items-center gap-1">
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[sev] }}
            />
            <span className="text-[9px] text-on-surface-variant uppercase tracking-wider">{sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default GlobeMap;
