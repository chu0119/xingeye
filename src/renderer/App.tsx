import React from 'react'
import { HashRouter, Routes, Route } from 'react-router-dom'
import AppShell from './components/layout/AppShell'
import Dashboard from './pages/Dashboard'
import ScanNew from './pages/ScanNew'
import ScanResult from './pages/ScanResult'
import Assets from './pages/Assets'
import Vulns from './pages/Vulns'
import Reports from './pages/Reports'
import Compare from './pages/Compare'
import Topology from './pages/Topology'
import Settings from './pages/Settings'

const App: React.FC = () => {
  return (
    <HashRouter>
      <AppShell>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/new" element={<ScanNew />} />
          <Route path="/scan/:id" element={<ScanResult />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/vulns" element={<Vulns />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="/topology" element={<Topology />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </AppShell>
    </HashRouter>
  )
}

export default App
