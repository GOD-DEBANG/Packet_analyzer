import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Analyzer from './pages/Analyzer';
import Traffic from './pages/Traffic';
import Rules from './pages/Rules';
import Flows from './pages/Flows';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/"         element={<Dashboard />} />
            <Route path="/analyzer" element={<Analyzer />} />
            <Route path="/traffic"  element={<Traffic />} />
            <Route path="/rules"    element={<Rules />} />
            <Route path="/flows"    element={<Flows />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
