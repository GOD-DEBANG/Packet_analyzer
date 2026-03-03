import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Upload, BarChart3, Shield, Network, Cpu
} from 'lucide-react';

const navItems = [
  { to: '/',         icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/analyzer', icon: Upload,          label: 'Analyzer'   },
  { to: '/traffic',  icon: BarChart3,       label: 'Traffic'    },
  { to: '/rules',    icon: Shield,          label: 'Rules'      },
  { to: '/flows',    icon: Network,         label: 'Flows'      },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">
          <Cpu size={20} color="#000" />
        </div>
        <div className="sidebar-logo-text">
          <span className="sidebar-logo-title">DPI Engine</span>
          <span className="sidebar-logo-subtitle">v2.0 • Packet Inspector</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <span className="nav-section-label">Navigation</span>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon className="nav-icon" size={18} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="engine-status">
          <span className="status-dot" />
          <div>
            <div className="status-label">Engine Ready</div>
            <div className="status-text">libpcap • v1.10</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
