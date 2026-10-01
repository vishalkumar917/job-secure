import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AnalysisLayout, AppLayout } from "./components/layout/AppLayout";
import { Loading } from "./components/ui";
import { useAuth } from "./hooks/useAuth";
import AnalysisProgressPage from "./pages/AnalysisProgressPage";
import AssistantPage from "./pages/AssistantPage";
import CaseDetailPage from "./pages/CaseDetailPage";
import CreateInvestigationPage from "./pages/CreateInvestigationPage";
import DashboardPage from "./pages/DashboardPage";
import FindingsPage from "./pages/FindingsPage";
import InvestigationsPage from "./pages/InvestigationsPage";
import IocExplorerPage from "./pages/IocExplorerPage";
import LoginPage from "./pages/LoginPage";
import MemoryAnalysisPage from "./pages/MemoryAnalysisPage";
import NetworkPage from "./pages/NetworkPage";
import OverviewPage from "./pages/OverviewPage";
import ProcessDetailPage from "./pages/ProcessDetailPage";
import ProcessesPage from "./pages/ProcessesPage";
import ReportsPage from "./pages/ReportsPage";
import SettingsPage from "./pages/SettingsPage";
import TimelinePage from "./pages/TimelinePage";
import UploadMemoryPage from "./pages/UploadMemoryPage";

export default function App() {
  const { user, ready } = useAuth();
  const location = useLocation();
  if (!ready) return <Loading label="Starting..." />;
  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace state={{ from: location.pathname }} />} />
      </Routes>
    );
  }
  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="investigations" element={<InvestigationsPage />} />
        <Route path="investigations/new" element={<CreateInvestigationPage />} />
        <Route path="investigations/:caseId" element={<CaseDetailPage />} />
        <Route path="investigations/:caseId/upload" element={<UploadMemoryPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="analysis/:jobId" element={<AnalysisLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="progress" element={<AnalysisProgressPage />} />
          <Route path="processes" element={<ProcessesPage />} />
          <Route path="processes/:pid" element={<ProcessDetailPage />} />
          <Route path="memory" element={<MemoryAnalysisPage />} />
          <Route path="network" element={<NetworkPage />} />
          <Route path="iocs" element={<IocExplorerPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="assistant" element={<AssistantPage />} />
          <Route path="reports" element={<ReportsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
