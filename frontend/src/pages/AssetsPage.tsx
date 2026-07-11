import { useState } from 'react';
import { useAlert } from '../components/AlertProvider';
import { BarChart } from '../components/Charts';

const AssetsPage = () => {
  const { showAlert } = useAlert();
  const [searchQuery, setSearchQuery] = useState('');
  const [cloudFilter, setCloudFilter] = useState('All Clouds');
  const [regionFilter, setRegionFilter] = useState('All Regions');
  const [statusFilter, setStatusFilter] = useState('All States');
  const [showMoreFilters, setShowMoreFilters] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  const handleExportCSV = () => {
    const headers = ['Name', 'ID', 'Provider', 'Region', 'Owner', 'Status', 'Last Scanned'];
    const rows = filteredAssets.map((a) => [
      a.name, a.id, a.provider, a.region, a.owner, a.status, a.lastScanned,
    ]);
    const csvContent = [headers, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cspm-assets-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showAlert('success', 'CSV Downloaded', `Exported ${filteredAssets.length} assets to CSV file.`);
  };

  const metricCards = [
    { label: 'TOTAL ASSETS', value: '12,842', trend: '+4% from last scan', icon: 'inventory_2', trendColor: 'text-secondary' },
    { label: 'COMPUTE', value: '4,120', subtext: 'EC2, Lambda, EKS', icon: 'computer' },
    { label: 'STORAGE', value: '2.4 PB', subtext: '852 S3 Buckets, 142 RDS', icon: 'database' },
    { label: 'CRITICAL ALERTS', value: '42', subtext: 'Requiring immediate action', icon: 'report', error: true },
  ];

  const assets = [
    {
      type: 'dns',
      name: 'prod-db-replica-01',
      id: 'i-0a2b3c4d5e6f7g8h9',
      provider: 'AWS',
      providerColor: 'bg-orange-500',
      region: 'us-east-1',
      owner: 'infra-team-alpha',
      ownerIcon: 'person',
      status: 'secure',
      lastScanned: '2 mins ago',
    },
    {
      type: 'folder_open',
      name: 'public-assets-archive',
      id: 'arn:aws:s3:::public-assets',
      provider: 'AWS',
      providerColor: 'bg-orange-500',
      region: 'us-west-2',
      owner: 'marketing-web',
      ownerIcon: 'person',
      status: 'misconfigured',
      lastScanned: '14 mins ago',
    },
    {
      type: 'verified_user',
      name: 'admin-role-super',
      id: 'Azure Active Directory',
      provider: 'Azure',
      providerColor: 'bg-blue-500',
      region: 'North Europe',
      owner: 'iam-core-service',
      ownerIcon: 'lock',
      status: 'vulnerable',
      lastScanned: 'Just now',
    },
    {
      type: 'router',
      name: 'vpc-main-gateway',
      id: '10.0.0.1 / igw-987654321',
      provider: 'AWS',
      providerColor: 'bg-orange-500',
      region: 'us-west-2',
      owner: 'networking-ops',
      ownerIcon: 'person',
      status: 'secure',
      lastScanned: '1 hour ago',
    },
    {
      type: 'cloud',
      name: 'gcp-compute-node-22',
      id: 'projects/p-98123/instances/22',
      provider: 'GCP',
      providerColor: 'bg-red-500',
      region: 'us-central1',
      owner: 'data-science',
      ownerIcon: 'person',
      status: 'misconfigured',
      lastScanned: '45 mins ago',
    },
  ];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'secure':
        return { bg: 'bg-secondary/10', border: 'border-secondary/20', dot: 'bg-secondary', text: 'text-secondary', label: 'SECURE' };
      case 'misconfigured':
        return { bg: 'bg-tertiary/10', border: 'border-tertiary/20', dot: 'bg-tertiary', text: 'text-tertiary', label: 'MISCONFIGURED' };
      case 'vulnerable':
        return { bg: 'bg-error/10', border: 'border-error/20', dot: 'bg-error', text: 'text-error', label: 'VULNERABLE' };
      default:
        return { bg: 'bg-outline/10', border: 'border-outline/20', dot: 'bg-outline', text: 'text-outline', label: 'UNKNOWN' };
    }
  };

  const filteredAssets = assets.filter((asset) => {
    const matchesSearch =
      searchQuery === '' ||
      asset.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCloud = cloudFilter === 'All Clouds' || asset.provider === cloudFilter;
    const matchesRegion = regionFilter === 'All Regions' || asset.region === regionFilter;
    const matchesState = statusFilter === 'All States' || asset.status === statusFilter.toLowerCase();
    return matchesSearch && matchesCloud && matchesRegion && matchesState;
  });

  const handleRowClick = (assetName: string) => {
    showAlert('info', 'Asset Details', `Opening configuration profile for asset: ${assetName}`);
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    showAlert('info', 'Page Switched', `Loading asset inventory page ${page}...`);
  };

  return (
    <main className="pt-16 pb-20 px-4 lg:px-6 max-w-7xl mx-auto space-y-6">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-gutter">
        {metricCards.map((card, index) => (
          <div
            key={index}
            className={`glass-panel p-4 rounded-xl flex flex-col justify-between border border-outline-variant/10 relative overflow-hidden ${
              card.error ? 'border-l-4 border-l-error' : ''
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="font-label-caps text-label-caps text-on-surface-variant">{card.label}</span>
              <span className={`material-symbols-outlined ${card.error ? 'text-error' : 'text-primary'} text-md`}>
                {card.icon}
              </span>
            </div>
            <div className="mt-4">
              <h2 className={`font-headline-lg text-headline-lg ${card.error ? 'text-error' : ''}`}>
                {card.value}
              </h2>
              {card.trend && (
                <div className={`flex items-center gap-1 ${card.trendColor} text-body-sm mt-1`}>
                  <span className="material-symbols-outlined text-sm">trending_up</span>
                  <span>{card.trend}</span>
                </div>
              )}
              {card.subtext && (
                <div className="text-body-sm text-on-surface-variant mt-1">{card.subtext}</div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Inventory Browser */}
      <section className="glass-panel rounded-xl overflow-hidden flex flex-col border border-outline-variant/10">
        {/* Toolbar */}
        <div className="p-4 border-b border-outline-variant/15 flex flex-wrap items-center gap-4 bg-surface-container">
          <div className="relative flex-1 min-w-[280px]">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm">
              search
            </span>
            <input
              type="text"
              className="w-full bg-surface-container-lowest border border-outline-variant/20 rounded-lg pl-10 pr-4 py-2 text-body-md focus:outline-none focus:border-primary transition-all text-on-surface"
              placeholder="Search assets by ID, name, or IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              className="bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm focus:outline-none focus:border-primary text-on-surface"
              value={cloudFilter}
              onChange={(e) => setCloudFilter(e.target.value)}
            >
              <option>All Clouds</option>
              <option>AWS</option>
              <option>Azure</option>
              <option>GCP</option>
            </select>
            <select
              className="bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm focus:outline-none focus:border-primary text-on-surface"
              value={regionFilter}
              onChange={(e) => setRegionFilter(e.target.value)}
            >
              <option>All Regions</option>
              <option>us-east-1</option>
              <option>us-west-2</option>
              <option>us-central1</option>
              <option>North Europe</option>
            </select>
            <button
              onClick={() => {
                setShowMoreFilters(!showMoreFilters);
                showAlert('info', 'Filter Expansion', `${!showMoreFilters ? 'Opened' : 'Closed'} advanced filters.`);
              }}
              className="bg-surface-container-highest hover:bg-outline-variant/40 border border-outline-variant/20 px-3 py-2 rounded-lg flex items-center gap-2 transition-colors text-on-surface"
            >
              <span className="material-symbols-outlined text-sm">filter_list</span>
              <span className="text-body-sm">More Filters</span>
            </button>
            <button
              onClick={handleExportCSV}
              className="bg-primary text-on-primary hover:brightness-110 px-4 py-2 rounded-lg font-bold text-body-sm transition-colors"
            >
              Export CSV
            </button>
          </div>
        </div>

        {/* More Filters Extended Panel */}
        {showMoreFilters && (
          <div className="p-4 bg-surface-container-low border-b border-outline-variant/15 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs text-on-surface-variant uppercase tracking-wider mb-2">Security State</label>
              <select
                className="w-full bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm text-on-surface focus:outline-none focus:border-primary"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option>All States</option>
                <option>Secure</option>
                <option>Misconfigured</option>
                <option>Vulnerable</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-on-surface-variant uppercase tracking-wider mb-2">Owner Group</label>
              <select
                className="w-full bg-surface-container-lowest border border-outline-variant/20 rounded-lg px-3 py-2 text-body-sm text-on-surface focus:outline-none focus:border-primary"
                onChange={(e) => showAlert('info', 'Filter Applied', `Filter by Owner Group: ${e.target.value}`)}
              >
                <option>All Teams</option>
                <option>infra-team-alpha</option>
                <option>marketing-web</option>
                <option>iam-core-service</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                onClick={() => {
                  setStatusFilter('All States');
                  setCloudFilter('All Clouds');
                  setRegionFilter('All Regions');
                  showAlert('success', 'Filters Reset', 'All inventory filters cleared.');
                }}
                className="w-full bg-surface-container-high hover:bg-surface-variant border border-outline-variant/20 py-2 rounded-lg text-body-sm font-bold text-on-surface text-center transition-colors"
              >
                Clear All Filters
              </button>
            </div>
          </div>
        )}

        {/* Assets Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[1000px]">
            <thead>
              <tr className="bg-surface-container-high border-b border-outline-variant/20">
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">
                  ASSET TYPE / NAME
                </th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">
                  PROVIDER / REGION
                </th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">
                  IDENTITY / OWNER
                </th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant">
                  SECURITY STATE
                </th>
                <th className="px-6 py-3 font-label-caps text-label-caps text-on-surface-variant text-right">
                  LAST SCANNED
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/10">
              {filteredAssets.length > 0 ? (
                filteredAssets.map((asset, index) => {
                  const statusInfo = getStatusBadge(asset.status);
                  return (
                    <tr
                      key={index}
                      onClick={() => handleRowClick(asset.name)}
                      className="hover:bg-primary/5 transition-colors group cursor-pointer"
                    >
                      <td className="px-6 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded bg-surface-container-highest flex items-center justify-center">
                            <span
                              className="material-symbols-outlined text-primary text-sm"
                              style={{ fontVariationSettings: "'FILL' 1" }}
                            >
                              {asset.type}
                            </span>
                          </div>
                          <div>
                            <div className="font-mono-data text-mono-data text-on-surface group-hover:text-primary transition-colors">
                              {asset.name}
                            </div>
                            <div className="text-[11px] text-on-surface-variant">{asset.id}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`w-4 h-4 ${asset.providerColor} rounded-sm`}></span>
                          <span className="text-body-sm text-on-surface">
                            {asset.provider} • {asset.region}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-3 text-body-sm text-on-surface">
                        <div className="flex items-center gap-1.5">
                          <span className="material-symbols-outlined text-xs text-on-surface-variant">{asset.ownerIcon}</span>
                          <span>{asset.owner}</span>
                        </div>
                      </td>
                      <td className="px-6 py-3">
                        <div
                          className={`flex items-center gap-2 px-2.5 py-0.5 rounded-full ${statusInfo.bg} border ${statusInfo.border} w-fit`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${statusInfo.dot}`}></span>
                          <span className={`text-[10px] uppercase font-bold tracking-wider ${statusInfo.text}`}>{statusInfo.label}</span>
                        </div>
                      </td>
                      <td className="px-6 py-3 text-right font-mono-data text-body-sm text-on-surface-variant">
                        {asset.lastScanned}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-on-surface-variant font-body-md">
                    No connected assets match current query and filter conditions.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 bg-surface-container flex items-center justify-between border-t border-outline-variant/15">
          <span className="text-body-sm text-on-surface-variant">
            Showing 1-{filteredAssets.length} of {filteredAssets.length} filtered assets
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="p-1.5 hover:bg-surface-container-highest rounded-lg disabled:opacity-30 border border-outline-variant/15 text-on-surface"
            >
              <span className="material-symbols-outlined text-md">chevron_left</span>
            </button>
            <button
              onClick={() => handlePageChange(1)}
              className={`w-8 h-8 flex items-center justify-center font-bold rounded-lg text-body-sm transition-all ${
                currentPage === 1 ? 'bg-primary text-on-primary' : 'hover:bg-surface-container-highest text-on-surface'
              }`}
            >
              1
            </button>
            <button
              onClick={() => handlePageChange(2)}
              className={`w-8 h-8 flex items-center justify-center font-bold rounded-lg text-body-sm transition-all ${
                currentPage === 2 ? 'bg-primary text-on-primary' : 'hover:bg-surface-container-highest text-on-surface'
              }`}
            >
              2
            </button>
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              className="p-1.5 hover:bg-surface-container-highest rounded-lg border border-outline-variant/15 text-on-surface"
            >
              <span className="material-symbols-outlined text-md">chevron_right</span>
            </button>
          </div>
        </div>
      </section>

      {/* Bottom Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-gutter mt-6">
        {/* Inventory Distribution */}
        <div className="glass-panel p-4 rounded-xl border border-outline-variant/10">
          <h3 className="font-headline-sm text-headline-sm mb-4">Inventory Distribution</h3>
          <BarChart
            height={130}
            data={[
              { label: 'AWS', value: 65, color: '#f97316' },
              { label: 'Azure', value: 25, color: '#3b82f6' },
              { label: 'GCP', value: 10, color: '#ef4444' },
            ]}
          />
        </div>

        {/* Inventory Hygiene */}
        <div className="glass-panel p-4 rounded-xl flex flex-col justify-center border border-outline-variant/10">
          <div className="flex items-center gap-4">
            <div className="relative w-20 h-20 flex-shrink-0">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="16" fill="none" stroke="#1c2026" strokeWidth="4" />
                <circle cx="18" cy="18" r="16" fill="none" stroke="#4edea3" strokeWidth="4" strokeDasharray="88 100" />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-sm font-bold text-on-surface">88%</span>
              </div>
            </div>
            <div>
              <h4 className="font-bold text-sm text-on-surface">Inventory Hygiene</h4>
              <p className="text-body-sm text-on-surface-variant mt-1 leading-relaxed">
                Compliance coverage stands at 88% across 12,842 assets, trending{' '}
                <span className="text-secondary font-bold">+2.1%</span> from last scan.
              </p>
              <button
                onClick={() => showAlert('info', 'Routing', 'Redirecting to policy frameworks page...')}
                className="mt-3 text-primary font-bold text-xs hover:underline flex items-center gap-1"
              >
                Review Policy Framework <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
};

export default AssetsPage;
